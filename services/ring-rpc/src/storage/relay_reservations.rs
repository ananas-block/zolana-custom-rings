//! One durable row per relay attempt, its budget charge, its upload lease and the send a restart must reconcile.

use sea_orm::{ConnectionTrait, DbErr, QueryResult, Statement, TransactionTrait, Value};
use solana_address::Address;
use solana_signature::Signature;
use zolana_ring_client::rpc::RelayId;

const TOTAL_SCOPE: [u8; 32] = [0; 32];

/// One blockhash lifetime of silence hands the attempt on. Expiry decides liveness alone. The generation
/// fence and the persisted send keep a holder that overruns from spending, however long it stalls.
const LEASE_SLOTS: u64 = 150;

const PHASE_OPEN: &str = "open";
const PHASE_BOUND: &str = "bound";
const PHASE_CLOSING: &str = "closing";

/// Zero funds nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayBudget {
    /// Reserved and spent over the store's life, only the operator raises it.
    pub total_lamports: u64,
    /// Outstanding at once under one key, with the fees of its attempts that never landed for good.
    pub signer_lamports: u64,
}

/// The account whose rent returns on release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReservedBuffer {
    pub ring: Address,
    pub buffer: Address,
}

/// Every claim raises the generation, and every spending statement compares it. A holder whose lease
/// lapsed and passed on loses at its next statement, before it can sign away another fee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lease {
    pub key: [u8; 32],
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptPhase {
    /// No message exists, the lease holder proves and uploads, a lapsed lease passes to a retry.
    Open,
    /// A stored relay names the row. The relay id never moves again, so a message that can land keeps
    /// its charge until settlement or proven expiry.
    Bound,
    /// Cleanup owns the row. A retry waits for the release, an upload can no longer resume.
    Closing,
}

/// A signed transaction that may be on the wire. Its last valid height decides expiry, slot age cannot,
/// because skipped slots leave a blockhash valid past any slot count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingSend {
    pub signature: Signature,
    pub last_valid_block_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reservation {
    pub key: [u8; 32],
    pub relay_id: RelayId,
    pub signer: Address,
    /// Zero until funded. An unfunded row dedupes the request and answers for no budget.
    pub lamports: u64,
    pub landing_rent: u64,
    pub buffer: Option<ReservedBuffer>,
    /// Frame writes landed, a retry resumes past them.
    pub uploaded: usize,
    pub proven: Option<String>,
    pub generation: u64,
    pub phase: AttemptPhase,
    pub pending: Option<PendingSend>,
}

/// The lease and the row as the claim left it.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Claim {
    pub lease: Lease,
    pub held: Reservation,
}

#[must_use]
pub(crate) struct Admit<'a> {
    pub key: [u8; 32],
    pub relay_id: &'a RelayId,
    pub signer: Address,
    pub slot: u64,
}

#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Claimed(Box<Claim>),
    /// A live lease or a cleanup holds the row.
    Busy,
    /// An earlier relay of the request names the row.
    Bound(Box<Reservation>),
}

#[must_use]
pub(crate) struct Fund {
    pub lease: Lease,
    pub lamports: u64,
    /// Every fee the attempt may pay. `lamports` less rent, so a spend inside it leaves rent whole.
    pub fee_allowance: u64,
    /// Held back from writes for the settlement and the close, an upload never eats the way out.
    pub closing_fees: u64,
    /// Rent the relay never recovers once its transaction lands.
    pub landing_rent: u64,
    pub buffer: Option<ReservedBuffer>,
    /// The proven frame, a retry of the request proves nothing again.
    pub proven: Option<String>,
    pub budget: RelayBudget,
}

#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FundOutcome {
    Held(Box<Reservation>),
    OverTotal,
    OverSigner,
    LeaseLost,
}

#[must_use]
pub(crate) struct Bind<'a> {
    pub lease: Lease,
    pub relay_id: &'a RelayId,
    /// The message's own fee, past the allowance the relay stores no message to pay for.
    pub fee: u64,
    pub slot: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendKind {
    /// Landing raises the upload cursor to `uploaded`.
    Write {
        uploaded: usize,
    },
    Close,
}

#[must_use]
pub(crate) struct BeginSend {
    pub lease: Lease,
    pub pending: PendingSend,
    pub fee: u64,
    pub kind: SendKind,
    pub slot: u64,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpendCheck {
    Accepted,
    OverAllowance,
    LeaseLost,
}

/// What the chain proved about a pending send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendEnd {
    /// Finalized success, the fee stays and a write's cursor advances.
    Landed,
    /// Finalized failure, the fee stays and nothing advances.
    Paid,
    /// Refused at preflight or past its last valid height, the fee was never paid and returns.
    Unsent,
}

/// Whether the attempt's message landed, and what the total keeps for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptEnd {
    /// The signer paid for a landed spend, its share returns whole. The total also keeps the rent and fee.
    Landed { lamports: u64 },
    /// No message landed, the charged fees stay on the total and on the signer's share for good.
    Unlanded,
}

#[must_use]
pub(crate) struct Release<'a> {
    pub key: &'a [u8; 32],
    /// A newer attempt under the key names another relay and keeps its row.
    pub relay_id: &'a RelayId,
    pub end: AttemptEnd,
}

#[must_use]
pub(crate) struct ClaimCleanup<'a> {
    /// As the caller selected it, a newer generation refuses the claim.
    pub held: &'a Reservation,
    pub slot: u64,
    /// An open row must be untouched since, the other phases have no upload left to exclude.
    pub abandoned_before: u64,
}

pub(crate) struct RelayReservations<'a, C> {
    db: &'a C,
}

fn value(bytes: &[u8]) -> Value {
    bytes.to_vec().into()
}

fn lamports_value(lamports: u64) -> Result<Value, DbErr> {
    i64::try_from(lamports)
        .map(Into::into)
        .map_err(|_| DbErr::Custom("lamports out of range".into()))
}

/// A key's row can be deleted and inserted again, a counter restarting there would hand a stalled
/// holder the new row's lease. The top bits stay clear for the raises and the signed column.
fn first_generation() -> u64 {
    rand::random::<u64>() >> 2
}

fn lease_until(slot: u64) -> Result<Value, DbErr> {
    lamports_value(slot.saturating_add(LEASE_SLOTS))
}

fn read_reservation(row: &QueryResult) -> Result<Reservation, DbErr> {
    let bytes32 = |column: &str| -> Result<[u8; 32], DbErr> {
        <[u8; 32]>::try_from(row.try_get::<Vec<u8>>("", column)?)
            .map_err(|_| DbErr::Custom(format!("{column} has another length")))
    };
    let optional = |column: &str| -> Result<Option<Address>, DbErr> {
        row.try_get::<Option<Vec<u8>>>("", column)?
            .map(|bytes| {
                <[u8; 32]>::try_from(bytes)
                    .map(Address::new_from_array)
                    .map_err(|_| DbErr::Custom(format!("{column} has another length")))
            })
            .transpose()
    };
    let buffer = optional("ring")?
        .zip(optional("buffer")?)
        .map(|(ring, buffer)| ReservedBuffer { ring, buffer });
    let number = |column: &str| -> Result<u64, DbErr> {
        u64::try_from(row.try_get::<i64>("", column)?)
            .map_err(|_| DbErr::Custom(format!("{column} out of range")))
    };
    let phase = match row.try_get::<String>("", "phase")?.as_str() {
        PHASE_OPEN => AttemptPhase::Open,
        PHASE_BOUND => AttemptPhase::Bound,
        PHASE_CLOSING => AttemptPhase::Closing,
        _ => return Err(DbErr::Custom("phase is corrupt".into())),
    };
    let pending = row
        .try_get::<Option<Vec<u8>>>("", "pending_signature")?
        .map(|signature| {
            let signature = <[u8; 64]>::try_from(signature)
                .map_err(|_| DbErr::Custom("pending_signature has another length".into()))?;
            Ok::<_, DbErr>(PendingSend {
                signature: Signature::from(signature),
                last_valid_block_height: number("pending_valid_height")?,
            })
        })
        .transpose()?;
    Ok(Reservation {
        key: bytes32("key")?,
        relay_id: RelayId(spr_indexer_api::Hash(bytes32("relay_id")?)),
        signer: Address::new_from_array(bytes32("signer")?),
        lamports: number("lamports")?,
        landing_rent: number("landing_rent")?,
        buffer,
        uploaded: usize::try_from(number("uploaded")?)
            .map_err(|_| DbErr::Custom("uploaded out of range".into()))?,
        proven: row.try_get("", "proven")?,
        generation: number("generation")?,
        phase,
        pending,
    })
}

const COLUMNS: &str = "key,relay_id,signer,lamports,landing_rent,ring,buffer,uploaded,proven,\
                       generation,phase,pending_signature,pending_valid_height";

impl<'a, C: ConnectionTrait> RelayReservations<'a, C> {
    pub fn new(db: &'a C) -> Self {
        Self { db }
    }

    fn statement(&self, sql: impl Into<String>, values: Vec<Value>) -> Statement {
        Statement::from_sql_and_values(self.db.get_database_backend(), sql.into(), values)
    }

    /// The durable admission of a signed request, taken before any proof or payment.
    pub async fn admit(&self, admit: Admit<'_>) -> Result<Admission, DbErr> {
        let Admit {
            key,
            relay_id,
            signer,
            slot,
        } = admit;
        // 1. The insert is the first caller's claim, the key's uniqueness makes it exclusive across
        // processes.
        let inserted = self
            .db
            .execute(self.statement(
                "INSERT INTO relay_reservations(key,relay_id,signer,lamports,fee_allowance,\
                 closing_fees,landing_rent,uploaded,spent,phase,generation,lease_until_slot,\
                 touched_slot) VALUES($1,$2,$3,0,0,0,0,0,0,$4,$7,$5,$6) \
                 ON CONFLICT(key) DO NOTHING",
                vec![
                    value(&key),
                    value(&relay_id.0 .0),
                    value(signer.as_ref()),
                    PHASE_OPEN.into(),
                    lease_until(slot)?,
                    lamports_value(slot)?,
                    lamports_value(first_generation())?,
                ],
            ))
            .await?
            .rows_affected();
        // 2. An open row with a lapsed lease passes to the new caller. The raised generation fences the old
        // holder. The relay id moves only here, where no message exists for an older id to land.
        let claimed = inserted != 0
            || self
                .db
                .execute(self.statement(
                    "UPDATE relay_reservations SET generation=generation+1, relay_id=$2, \
                     lease_until_slot=$3, touched_slot=$4 \
                     WHERE key=$1 AND phase=$5 AND lease_until_slot < $4",
                    vec![
                        value(&key),
                        value(&relay_id.0 .0),
                        lease_until(slot)?,
                        lamports_value(slot)?,
                        PHASE_OPEN.into(),
                    ],
                ))
                .await?
                .rows_affected()
                != 0;
        let Some(held) = self.get(&key).await? else {
            return Ok(Admission::Busy);
        };
        if claimed {
            return Ok(Admission::Claimed(Box::new(Claim {
                lease: Lease {
                    key,
                    generation: held.generation,
                },
                held,
            })));
        }
        // 3. Any other row answers with its phase and changes nothing, a bound row keeps its live message.
        Ok(match held.phase {
            AttemptPhase::Bound => Admission::Bound(Box::new(held)),
            AttemptPhase::Open | AttemptPhase::Closing => Admission::Busy,
        })
    }

    pub async fn by_relay(&self, relay_id: &RelayId) -> Result<Option<Reservation>, DbErr> {
        let row = self
            .db
            .query_one(self.statement(
                format!("SELECT {COLUMNS} FROM relay_reservations WHERE relay_id=$1"),
                vec![value(&relay_id.0 .0)],
            ))
            .await?;
        row.as_ref().map(read_reservation).transpose()
    }

    /// Attaches the row to the stored relay, in the transaction that stores it. A holder that lost the
    /// lease stores no message, and cleanup cannot close a buffer a stored settlement still reads.
    pub async fn bind(&self, bind: Bind<'_>) -> Result<SpendCheck, DbErr> {
        let Bind {
            lease,
            relay_id,
            fee,
            slot,
        } = bind;
        let updated = self
            .db
            .execute(self.statement(
                "UPDATE relay_reservations SET phase=$3, relay_id=$4, lease_until_slot=0, \
                 touched_slot=$5 WHERE key=$1 AND generation=$2 AND phase=$6 \
                 AND pending_signature IS NULL AND (lamports=0 OR spent+$7 <= fee_allowance)",
                vec![
                    value(&lease.key),
                    lamports_value(lease.generation)?,
                    PHASE_BOUND.into(),
                    value(&relay_id.0 .0),
                    lamports_value(slot)?,
                    PHASE_OPEN.into(),
                    lamports_value(fee)?,
                ],
            ))
            .await?
            .rows_affected();
        self.spend_check(&lease, updated).await
    }

    /// Persists the signed send and charges its fee in one statement, before a byte leaves. A crash after
    /// it leaves a signature to reconcile and a fee already counted, and a fee past the allowance never
    /// sends. A write also leaves `closing_fees` untouched, retried writes cannot strand the buffer rent.
    /// One send at a time, an unreconciled one refuses the next.
    pub async fn begin_send(&self, send: BeginSend) -> Result<SpendCheck, DbErr> {
        let BeginSend {
            lease,
            pending,
            fee,
            kind,
            slot,
        } = send;
        let (kept, uploaded) = match kind {
            SendKind::Write { uploaded } => (
                "closing_fees",
                Some(i64::try_from(uploaded).map_err(|_| DbErr::Custom("count range".into()))?),
            ),
            SendKind::Close => ("0", None),
        };
        let updated = self
            .db
            .execute(self.statement(
                format!(
                    "UPDATE relay_reservations SET spent=spent+$3, pending_signature=$4, \
                     pending_valid_height=$5, pending_fee=$3, pending_upload=$6, touched_slot=$7, \
                     lease_until_slot=$8 WHERE key=$1 AND generation=$2 \
                     AND pending_signature IS NULL AND spent+$3+{kept} <= fee_allowance"
                ),
                vec![
                    value(&lease.key),
                    lamports_value(lease.generation)?,
                    lamports_value(fee)?,
                    value(pending.signature.as_ref()),
                    lamports_value(pending.last_valid_block_height)?,
                    Value::BigInt(uploaded),
                    lamports_value(slot)?,
                    lease_until(slot)?,
                ],
            ))
            .await?
            .rows_affected();
        self.spend_check(&lease, updated).await
    }

    /// `false` when a newer holder took the row or the signature is no longer the pending one, the
    /// caller stops without touching the cursor. Each landed send refreshes the window, a slow upload is
    /// no abandoned one.
    #[must_use = "a false outcome means the lease passed on"]
    pub async fn conclude_send(
        &self,
        lease: &Lease,
        signature: &Signature,
        end: SendEnd,
        slot: u64,
    ) -> Result<bool, DbErr> {
        let outcome = match end {
            SendEnd::Landed => "uploaded=COALESCE(pending_upload,uploaded)",
            SendEnd::Paid => "uploaded=uploaded",
            SendEnd::Unsent => "spent=spent-pending_fee",
        };
        Ok(self
            .db
            .execute(self.statement(
                format!(
                    "UPDATE relay_reservations SET {outcome}, pending_signature=NULL, \
                     pending_valid_height=NULL, pending_fee=NULL, pending_upload=NULL, \
                     touched_slot=$4, lease_until_slot=$5 \
                     WHERE key=$1 AND generation=$2 AND pending_signature=$3"
                ),
                vec![
                    value(&lease.key),
                    lamports_value(lease.generation)?,
                    value(signature.as_ref()),
                    lamports_value(slot)?,
                    lease_until(slot)?,
                ],
            ))
            .await?
            .rows_affected()
            != 0)
    }

    /// The fee of a relay message that landed and failed, in the transaction that stores the failure. A
    /// crash cannot count it twice. Bound by `bind`, an unfunded row answers for no budget.
    pub async fn charge_landed(&self, relay_id: &RelayId, fee: u64) -> Result<(), DbErr> {
        self.db
            .execute(self.statement(
                "UPDATE relay_reservations SET spent=spent+$2 WHERE relay_id=$1 AND lamports<>0",
                vec![value(&relay_id.0 .0), lamports_value(fee)?],
            ))
            .await?;
        Ok(())
    }

    /// Oldest first, untouched since `before_slot` with no live lease. A selection is only a hint, the
    /// row can move before its claim.
    pub async fn abandoned(
        &self,
        before_slot: u64,
        slot: u64,
        limit: u64,
    ) -> Result<Vec<Reservation>, DbErr> {
        self.db
            .query_all(self.statement(
                format!(
                    "SELECT {COLUMNS} FROM relay_reservations WHERE touched_slot < $1 \
                     AND lease_until_slot < $2 ORDER BY touched_slot LIMIT $3"
                ),
                vec![
                    lamports_value(before_slot)?,
                    lamports_value(slot)?,
                    lamports_value(limit)?,
                ],
            ))
            .await?
            .iter()
            .map(read_reservation)
            .collect()
    }

    /// The one compare and update between upload and cleanup, each side rechecked at its own statement.
    /// A retry that resumed raised the generation or refreshed the age, either refuses a stale selection.
    /// A won claim raises the generation in turn, a still running upload stops at its next send.
    pub async fn claim_cleanup(&self, claim: ClaimCleanup<'_>) -> Result<Option<Claim>, DbErr> {
        let ClaimCleanup {
            held,
            slot,
            abandoned_before,
        } = claim;
        let updated = self
            .db
            .execute(self.statement(
                "UPDATE relay_reservations SET phase=$3, generation=generation+1, \
                 lease_until_slot=$4 WHERE key=$1 AND generation=$2 AND relay_id=$8 \
                 AND lease_until_slot < $5 AND (phase<>$6 OR touched_slot < $7)",
                vec![
                    value(&held.key),
                    lamports_value(held.generation)?,
                    PHASE_CLOSING.into(),
                    lease_until(slot)?,
                    lamports_value(slot)?,
                    PHASE_OPEN.into(),
                    lamports_value(abandoned_before)?,
                    value(&held.relay_id.0 .0),
                ],
            ))
            .await?
            .rows_affected();
        if updated == 0 {
            return Ok(None);
        }
        Ok(self.get(&held.key).await?.map(|held| Claim {
            lease: Lease {
                key: held.key,
                generation: held.generation,
            },
            held,
        }))
    }

    /// Stops holding the row. An open row that spent nothing leaves no trace, a retry starts over.
    /// Everything else stays for a retry or the sweep to claim at once.
    pub async fn yield_lease(&self, lease: &Lease) -> Result<(), DbErr> {
        let deleted = self
            .db
            .execute(self.statement(
                "DELETE FROM relay_reservations WHERE key=$1 AND generation=$2 AND phase=$3 \
                 AND lamports=0 AND pending_signature IS NULL",
                vec![
                    value(&lease.key),
                    lamports_value(lease.generation)?,
                    PHASE_OPEN.into(),
                ],
            ))
            .await?
            .rows_affected();
        if deleted == 0 {
            self.db
                .execute(self.statement(
                    "UPDATE relay_reservations SET lease_until_slot=0 \
                     WHERE key=$1 AND generation=$2",
                    vec![value(&lease.key), lamports_value(lease.generation)?],
                ))
                .await?;
        }
        Ok(())
    }

    pub async fn get(&self, key: &[u8; 32]) -> Result<Option<Reservation>, DbErr> {
        let row = self
            .db
            .query_one(self.statement(
                format!("SELECT {COLUMNS} FROM relay_reservations WHERE key=$1"),
                vec![value(key)],
            ))
            .await?;
        row.as_ref().map(read_reservation).transpose()
    }

    /// Zero rows means a newer holder, a pending send or a spend past the allowance, the row tells them
    /// apart. A pending send under the same lease reads as lost too, only a reconciling holder clears it.
    async fn spend_check(&self, lease: &Lease, updated: u64) -> Result<SpendCheck, DbErr> {
        if updated != 0 {
            return Ok(SpendCheck::Accepted);
        }
        Ok(match self.get(&lease.key).await? {
            Some(held) if held.generation == lease.generation && held.pending.is_none() => {
                SpendCheck::OverAllowance
            }
            _ => SpendCheck::LeaseLost,
        })
    }
}

impl<C: ConnectionTrait + TransactionTrait> RelayReservations<'_, C> {
    /// Moves the admitted row to its budget charge, the counters and the row commit together or not at
    /// all. A row funded by an earlier holder keeps its charge and answers as it stands.
    pub async fn fund(&self, fund: Fund) -> Result<FundOutcome, DbErr> {
        let Fund {
            lease,
            lamports,
            fee_allowance,
            closing_fees,
            landing_rent,
            buffer,
            proven,
            budget,
        } = fund;
        let backend = self.db.get_database_backend();
        let transaction = self.db.begin().await?;
        let updated = transaction
            .execute(Statement::from_sql_and_values(
                backend,
                "UPDATE relay_reservations SET lamports=$3, fee_allowance=$4, closing_fees=$5, \
                 landing_rent=$6, ring=$7, buffer=$8, proven=$9 \
                 WHERE key=$1 AND generation=$2 AND lamports=0",
                vec![
                    value(&lease.key),
                    lamports_value(lease.generation)?,
                    lamports_value(lamports)?,
                    lamports_value(fee_allowance)?,
                    lamports_value(closing_fees)?,
                    lamports_value(landing_rent)?,
                    Value::Bytes(buffer.map(|held| Box::new(held.ring.as_ref().to_vec()))),
                    Value::Bytes(buffer.map(|held| Box::new(held.buffer.as_ref().to_vec()))),
                    Value::String(proven.map(Box::new)),
                ],
            ))
            .await?
            .rows_affected();
        if updated == 0 {
            transaction.rollback().await?;
            return Ok(match self.get(&lease.key).await? {
                Some(held) if held.generation == lease.generation => {
                    FundOutcome::Held(Box::new(held))
                }
                _ => FundOutcome::LeaseLost,
            });
        }
        let signer = transaction
            .query_one(Statement::from_sql_and_values(
                backend,
                "SELECT signer FROM relay_reservations WHERE key=$1",
                vec![value(&lease.key)],
            ))
            .await?
            .ok_or_else(|| DbErr::Custom("a reservation vanished".into()))?
            .try_get::<Vec<u8>>("", "signer")?;
        let raise = |scope: &[u8], bound: u64| -> Result<Statement, DbErr> {
            Ok(Statement::from_sql_and_values(
                backend,
                "INSERT INTO relay_reserved(scope,committed) SELECT $1,$2 WHERE $2 <= $3 \
                 ON CONFLICT(scope) DO UPDATE SET committed = relay_reserved.committed + $2 \
                 WHERE relay_reserved.committed + $2 <= $3",
                vec![
                    value(scope),
                    lamports_value(lamports)?,
                    lamports_value(bound)?,
                ],
            ))
        };
        if transaction
            .execute(raise(&TOTAL_SCOPE, budget.total_lamports)?)
            .await?
            .rows_affected()
            == 0
        {
            transaction.rollback().await?;
            return Ok(FundOutcome::OverTotal);
        }
        if transaction
            .execute(raise(&signer, budget.signer_lamports)?)
            .await?
            .rows_affected()
            == 0
        {
            transaction.rollback().await?;
            return Ok(FundOutcome::OverSigner);
        }
        transaction.commit().await?;
        self.get(&lease.key)
            .await?
            .map(|held| FundOutcome::Held(Box::new(held)))
            .ok_or_else(|| DbErr::Custom("a reservation vanished".into()))
    }

    /// A pending send keeps the row, its fee and the rent stay held until the chain proves its outcome.
    /// The delete reads what it removes in one statement, a concurrent charge cannot slip past it.
    pub async fn release(&self, release: Release<'_>) -> Result<(), DbErr> {
        let Release { key, relay_id, end } = release;
        let backend = self.db.get_database_backend();
        let transaction = self.db.begin().await?;
        let row = transaction
            .query_one(Statement::from_sql_and_values(
                backend,
                "DELETE FROM relay_reservations WHERE key=$1 AND relay_id=$2 \
                 AND pending_signature IS NULL RETURNING lamports,spent,signer",
                vec![value(key), value(&relay_id.0 .0)],
            ))
            .await?;
        let Some(row) = row else {
            return transaction.commit().await;
        };
        let lamports: i64 = row.try_get("", "lamports")?;
        // An unfunded row raised no counter.
        if lamports == 0 {
            return transaction.commit().await;
        }
        let spent: i64 = row.try_get("", "spent")?;
        let signer: Vec<u8> = row.try_get("", "signer")?;
        let (to_total, to_signer) = match end {
            AttemptEnd::Landed { lamports: landed } => (
                i128::from(lamports) - i128::from(spent) - i128::from(landed),
                i128::from(lamports),
            ),
            AttemptEnd::Unlanded => {
                let unspent = i128::from(lamports) - i128::from(spent);
                (unspent, unspent)
            }
        };
        let returned = |lamports: i128| {
            i64::try_from(lamports)
                .map_err(|_| DbErr::Custom("returned lamports out of range".into()))
        };
        let lower = |scope: &[u8], lamports: i64| {
            Statement::from_sql_and_values(
                backend,
                "UPDATE relay_reserved SET committed = committed - $2 WHERE scope=$1",
                vec![value(scope), lamports.into()],
            )
        };
        transaction
            .execute(lower(&TOTAL_SCOPE, returned(to_total)?))
            .await?;
        transaction
            .execute(lower(&signer, returned(to_signer)?))
            .await?;
        // Fresh keys leave no counter row behind.
        transaction
            .execute(Statement::from_sql_and_values(
                backend,
                "DELETE FROM relay_reserved WHERE scope=$1 AND committed=0",
                vec![value(&signer)],
            ))
            .await?;
        transaction.commit().await
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;

    use super::*;
    use crate::database::Store;

    const BUDGET: RelayBudget = RelayBudget {
        total_lamports: 100,
        signer_lamports: 60,
    };
    const NO_LIMIT: RelayBudget = RelayBudget {
        total_lamports: 1_000,
        signer_lamports: 1_000,
    };
    /// Past every lease a test takes.
    const LATER: u64 = 10_000;

    fn relay_id(byte: u8) -> RelayId {
        RelayId(spr_indexer_api::Hash([byte; 32]))
    }

    fn signer(byte: u8) -> Address {
        Address::new_from_array([byte; 32])
    }

    fn pending(byte: u8) -> PendingSend {
        PendingSend {
            signature: Signature::from([byte; 64]),
            last_valid_block_height: 500,
        }
    }

    fn write_of(lease: Lease, byte: u8, fee: u64) -> BeginSend {
        BeginSend {
            lease,
            pending: pending(byte),
            fee,
            kind: SendKind::Write { uploaded: 1 },
            slot: 11,
        }
    }

    type Store0<'a> = RelayReservations<'a, DatabaseConnection>;

    /// Releases the row a `key` of `claim` names, unlanded.
    async fn release_row(store: &Store0<'_>, key: u8) {
        store
            .release(Release {
                key: &[key; 32],
                relay_id: &relay_id(key),
                end: AttemptEnd::Unlanded,
            })
            .await
            .expect("release");
    }

    async fn claim(store: &Store0<'_>, key: u8, who: Address, slot: u64) -> Claim {
        let id = relay_id(key);
        let admission = store
            .admit(Admit {
                key: [key; 32],
                relay_id: &id,
                signer: who,
                slot,
            })
            .await
            .expect("admit");
        match admission {
            Admission::Claimed(claim) => *claim,
            other => panic!("not claimed {other:?}"),
        }
    }

    fn funding(lease: Lease, lamports: u64, budget: RelayBudget) -> Fund {
        Fund {
            lease,
            lamports,
            fee_allowance: lamports,
            closing_fees: 0,
            landing_rent: 0,
            buffer: None,
            proven: None,
            budget,
        }
    }

    async fn reserve(store: &Store0<'_>, key: u8, who: Address, lamports: u64) -> FundOutcome {
        let claim = claim(store, key, who, 1).await;
        store
            .fund(funding(claim.lease, lamports, BUDGET))
            .await
            .expect("fund")
    }

    /// A funded row, its allowance of 30 keeps 10 for the way out.
    async fn uploading(store: &Store0<'_>) -> Claim {
        let claim = claim(store, 1, signer(1), 10).await;
        let funded = store
            .fund(Fund {
                fee_allowance: 30,
                closing_fees: 10,
                ..funding(claim.lease, 50, NO_LIMIT)
            })
            .await
            .expect("fund");
        assert!(matches!(funded, FundOutcome::Held(_)));
        claim
    }

    #[tokio::test]
    async fn the_bounds_refuse_and_a_release_returns_the_charge_once() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let FundOutcome::Held(first) = reserve(&store, 1, signer(1), 60).await else {
            panic!("within both bounds");
        };
        assert_eq!(
            reserve(&store, 2, signer(1), 1).await,
            FundOutcome::OverSigner
        );
        assert!(matches!(
            reserve(&store, 3, signer(2), 40).await,
            FundOutcome::Held(_)
        ));
        assert_eq!(
            reserve(&store, 4, signer(3), 1).await,
            FundOutcome::OverTotal
        );
        store
            .release(Release {
                key: &first.key,
                relay_id: &first.relay_id,
                end: AttemptEnd::Unlanded,
            })
            .await
            .expect("release");
        release_row(&store, 1).await;
        assert!(matches!(
            reserve(&store, 6, signer(3), 60).await,
            FundOutcome::Held(_)
        ));
        assert_eq!(
            reserve(&store, 7, signer(4), 1).await,
            FundOutcome::OverTotal
        );
    }

    #[tokio::test]
    async fn a_refused_funding_keeps_no_charge_and_its_yield_leaves_no_row() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let held = claim(&store, 1, signer(1), 1).await;
        assert_eq!(
            store
                .fund(funding(held.lease, 61, BUDGET))
                .await
                .expect("fund"),
            FundOutcome::OverSigner
        );
        store.yield_lease(&held.lease).await.expect("yield");
        assert_eq!(store.get(&held.lease.key).await.expect("read"), None);
    }

    #[tokio::test]
    async fn a_live_lease_turns_a_second_admission_away_and_a_lapsed_one_fences_its_holder() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let first = claim(&store, 1, signer(1), 10).await;
        let retry = relay_id(9);
        let again = |slot| Admit {
            key: [1; 32],
            relay_id: &retry,
            signer: signer(1),
            slot,
        };
        assert_eq!(
            store.admit(again(11)).await.expect("admit"),
            Admission::Busy
        );

        let Admission::Claimed(second) = store.admit(again(LATER)).await.expect("admit") else {
            panic!("the lease lapsed");
        };
        assert_eq!(second.held.relay_id, retry);
        assert_eq!(
            store
                .fund(funding(first.lease, 10, NO_LIMIT))
                .await
                .expect("fund"),
            FundOutcome::LeaseLost
        );
        assert_eq!(
            store
                .begin_send(write_of(first.lease, 7, 0))
                .await
                .expect("begin"),
            SpendCheck::LeaseLost
        );
        assert!(!store
            .conclude_send(&first.lease, &pending(7).signature, SendEnd::Landed, LATER)
            .await
            .expect("conclude"));
    }

    #[tokio::test]
    async fn a_held_row_keeps_its_upload_progress_and_its_charge_across_a_resume() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let first = uploading(&store).await;
        assert_eq!(
            store
                .begin_send(write_of(first.lease, 7, 5))
                .await
                .expect("begin"),
            SpendCheck::Accepted
        );
        assert!(store
            .conclude_send(&first.lease, &pending(7).signature, SendEnd::Landed, 12)
            .await
            .expect("conclude"));
        store.yield_lease(&first.lease).await.expect("yield");

        let resumed = claim(&store, 1, signer(1), 13).await;
        assert_eq!(resumed.held.uploaded, 1);
        assert_eq!(resumed.held.lamports, 50);
        assert!(matches!(
            store
                .fund(funding(resumed.lease, 999, NO_LIMIT))
                .await
                .expect("fund"),
            FundOutcome::Held(held) if held.lamports == 50
        ));
    }

    #[tokio::test]
    async fn a_charge_past_the_allowance_refuses_and_a_write_cannot_spend_the_way_out() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let held = uploading(&store).await;
        assert_eq!(
            store
                .begin_send(write_of(held.lease, 7, 21))
                .await
                .expect("begin"),
            SpendCheck::OverAllowance
        );
        assert_eq!(
            store
                .get(&held.lease.key)
                .await
                .expect("read")
                .unwrap()
                .pending,
            None
        );
        assert_eq!(
            store
                .begin_send(write_of(held.lease, 7, 20))
                .await
                .expect("begin"),
            SpendCheck::Accepted
        );
        assert!(store
            .conclude_send(&held.lease, &pending(7).signature, SendEnd::Paid, 12)
            .await
            .expect("conclude"));
        assert_eq!(
            store
                .begin_send(write_of(held.lease, 8, 1))
                .await
                .expect("begin"),
            SpendCheck::OverAllowance
        );
        // The closing share still pays the close.
        assert_eq!(
            store
                .begin_send(BeginSend {
                    kind: SendKind::Close,
                    fee: 10,
                    ..write_of(held.lease, 8, 0)
                })
                .await
                .expect("begin"),
            SpendCheck::Accepted
        );
    }

    #[tokio::test]
    async fn an_unsent_write_returns_its_fee_and_a_paid_one_keeps_it() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let held = uploading(&store).await;
        for _ in 0..3 {
            assert_eq!(
                store
                    .begin_send(write_of(held.lease, 7, 20))
                    .await
                    .expect("begin"),
                SpendCheck::Accepted
            );
            assert!(store
                .conclude_send(&held.lease, &pending(7).signature, SendEnd::Unsent, 12)
                .await
                .expect("conclude"));
        }
        let row = store.get(&held.lease.key).await.expect("read").unwrap();
        assert_eq!(row.uploaded, 0);
        release_row(&store, 1).await;
        // Nothing was spent, the whole charge returned.
        assert!(matches!(
            reserve(&store, 2, signer(2), 60).await,
            FundOutcome::Held(_)
        ));
        assert!(matches!(
            reserve(&store, 3, signer(3), 40).await,
            FundOutcome::Held(_)
        ));
    }

    #[tokio::test]
    async fn a_pending_send_keeps_the_row_and_refuses_the_next_send_and_the_binding() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let held = uploading(&store).await;
        assert_eq!(
            store
                .begin_send(write_of(held.lease, 7, 5))
                .await
                .expect("begin"),
            SpendCheck::Accepted
        );
        assert_eq!(
            store
                .begin_send(write_of(held.lease, 8, 5))
                .await
                .expect("begin"),
            SpendCheck::LeaseLost
        );
        let bound = store
            .bind(Bind {
                lease: held.lease,
                relay_id: &relay_id(1),
                fee: 0,
                slot: 12,
            })
            .await
            .expect("bind");
        assert_eq!(bound, SpendCheck::LeaseLost);

        release_row(&store, 1).await;
        let row = store
            .get(&held.lease.key)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(row.pending, Some(pending(7)));
    }

    #[tokio::test]
    async fn a_stale_selection_loses_to_a_resumed_upload() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let first = uploading(&store).await;
        store.yield_lease(&first.lease).await.expect("yield");
        let [selected] = store
            .abandoned(LATER, LATER, 8)
            .await
            .expect("read")
            .try_into()
            .expect("one row");

        let resumed = claim(&store, 1, signer(1), LATER).await;
        let claim = store
            .claim_cleanup(ClaimCleanup {
                held: &selected,
                slot: LATER + 1,
                abandoned_before: LATER,
            })
            .await
            .expect("claim");
        assert_eq!(claim, None);
        assert_eq!(
            store
                .begin_send(write_of(resumed.lease, 7, 5))
                .await
                .expect("begin"),
            SpendCheck::Accepted
        );
    }

    /// A bound row has no lease and no age left to refuse, only the generation does.
    #[tokio::test]
    async fn a_stale_selection_loses_to_a_row_a_retry_bound() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let first = uploading(&store).await;
        store.yield_lease(&first.lease).await.expect("yield");
        let [selected] = store
            .abandoned(LATER, LATER, 8)
            .await
            .expect("read")
            .try_into()
            .expect("one row");

        let resumed = claim(&store, 1, signer(1), LATER).await;
        let live = relay_id(9);
        assert_eq!(
            store
                .bind(Bind {
                    lease: resumed.lease,
                    relay_id: &live,
                    fee: 5,
                    slot: LATER,
                })
                .await
                .expect("bind"),
            SpendCheck::Accepted
        );
        let claim = store
            .claim_cleanup(ClaimCleanup {
                held: &selected,
                slot: LATER + 1,
                abandoned_before: LATER,
            })
            .await
            .expect("claim");

        assert_eq!(claim, None);
        let row = store.by_relay(&live).await.expect("read").expect("row");
        assert_eq!(row.phase, AttemptPhase::Bound);
    }

    /// A row of the key's earlier attempt, released, then inserted again for another relay.
    async fn reused_key(store: &Store0<'_>) -> (Reservation, Reservation) {
        let first = claim(store, 1, signer(1), 1).await;
        let bound = store
            .bind(Bind {
                lease: first.lease,
                relay_id: &relay_id(1),
                fee: 0,
                slot: 1,
            })
            .await
            .expect("bind");
        assert_eq!(bound, SpendCheck::Accepted);
        let selected = store.get(&[1; 32]).await.expect("read").expect("row");
        release_row(store, 1).await;

        let newer = relay_id(2);
        let Admission::Claimed(second) = store
            .admit(Admit {
                key: [1; 32],
                relay_id: &newer,
                signer: signer(1),
                slot: 2,
            })
            .await
            .expect("admit")
        else {
            panic!("the key is free");
        };
        let bound = store
            .bind(Bind {
                lease: second.lease,
                relay_id: &newer,
                fee: 0,
                slot: 2,
            })
            .await
            .expect("bind");
        assert_eq!(bound, SpendCheck::Accepted);
        let live = store.get(&[1; 32]).await.expect("read").expect("row");
        (selected, live)
    }

    #[tokio::test]
    async fn a_stale_selection_never_claims_the_next_attempt_of_its_key() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let (mut selected, live) = reused_key(&store).await;
        // The relay id alone must refuse, whatever the generations read.
        selected.generation = live.generation;

        let claim = store
            .claim_cleanup(ClaimCleanup {
                held: &selected,
                slot: LATER,
                abandoned_before: LATER,
            })
            .await
            .expect("claim");

        assert_eq!(claim, None);
        assert_eq!(store.get(&[1; 32]).await.expect("read"), Some(live));
    }

    #[tokio::test]
    async fn a_stale_landed_release_never_deletes_the_next_attempt_of_its_key() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let (selected, live) = reused_key(&store).await;

        store
            .release(Release {
                key: &selected.key,
                relay_id: &selected.relay_id,
                end: AttemptEnd::Landed { lamports: 5 },
            })
            .await
            .expect("release");

        assert_eq!(store.get(&[1; 32]).await.expect("read"), Some(live));
    }

    /// The row is gone and the key's next row starts over, the old holder must not pass as its holder.
    #[tokio::test]
    async fn a_stalled_holder_loses_to_the_next_row_of_its_key() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let stalled = uploading(&store).await;
        release_row(&store, 1).await;

        let next = uploading(&store).await;

        assert_ne!(stalled.lease, next.lease);
        assert_eq!(
            store
                .begin_send(write_of(stalled.lease, 7, 5))
                .await
                .expect("begin"),
            SpendCheck::LeaseLost
        );
    }

    #[tokio::test]
    async fn an_unlanded_attempt_keeps_its_fees_on_the_signers_share() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let held = claim(&store, 1, signer(1), 1).await;
        let funded = store
            .fund(funding(held.lease, 60, BUDGET))
            .await
            .expect("fund");
        assert!(matches!(funded, FundOutcome::Held(_)));
        assert_eq!(
            store
                .begin_send(write_of(held.lease, 7, 10))
                .await
                .expect("begin"),
            SpendCheck::Accepted
        );
        assert!(store
            .conclude_send(&held.lease, &pending(7).signature, SendEnd::Paid, 12)
            .await
            .expect("conclude"));
        release_row(&store, 1).await;

        // The signer's 60 holds the 10 spent, a whole share past it refuses.
        assert_eq!(
            reserve(&store, 2, signer(1), 51).await,
            FundOutcome::OverSigner
        );
        assert!(matches!(
            reserve(&store, 3, signer(1), 50).await,
            FundOutcome::Held(_)
        ));
    }

    #[tokio::test]
    async fn a_won_cleanup_stops_the_old_upload_and_turns_a_retry_away() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let first = uploading(&store).await;
        store.yield_lease(&first.lease).await.expect("yield");
        let selected = store.get(&first.lease.key).await.expect("read").unwrap();
        let young = ClaimCleanup {
            held: &selected,
            slot: LATER,
            abandoned_before: 5,
        };
        assert_eq!(store.claim_cleanup(young).await.expect("claim"), None);

        let won = store
            .claim_cleanup(ClaimCleanup {
                held: &selected,
                slot: LATER,
                abandoned_before: LATER,
            })
            .await
            .expect("claim")
            .expect("won");

        assert_eq!(
            store
                .begin_send(write_of(first.lease, 7, 5))
                .await
                .expect("begin"),
            SpendCheck::LeaseLost
        );
        let retry = relay_id(1);
        let admitted = store
            .admit(Admit {
                key: [1; 32],
                relay_id: &retry,
                signer: signer(1),
                slot: LATER * 2,
            })
            .await
            .expect("admit");
        assert_eq!(admitted, Admission::Busy);
        release_row(&store, 1).await;
        assert_eq!(store.get(&won.lease.key).await.expect("read"), None);
    }

    #[tokio::test]
    async fn a_bound_row_keeps_its_relay_and_only_the_message_fee_fits() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let held = uploading(&store).await;
        let live = relay_id(1);
        let bind = |fee| Bind {
            lease: held.lease,
            relay_id: &live,
            fee,
            slot: 12,
        };
        assert_eq!(
            store.bind(bind(31)).await.expect("bind"),
            SpendCheck::OverAllowance
        );
        assert_eq!(
            store.bind(bind(30)).await.expect("bind"),
            SpendCheck::Accepted
        );

        let fresh = relay_id(9);
        let Admission::Bound(bound) = store
            .admit(Admit {
                key: [1; 32],
                relay_id: &fresh,
                signer: signer(1),
                slot: LATER,
            })
            .await
            .expect("admit")
        else {
            panic!("the live relay holds the row");
        };
        assert_eq!(bound.relay_id, live);
        assert_eq!(store.by_relay(&fresh).await.expect("read"), None);
    }

    #[tokio::test]
    async fn the_total_keeps_charged_fees_and_landed_rent_and_the_signer_share_returns() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let held = claim(&store, 1, signer(1), 1).await;
        assert!(matches!(
            store
                .fund(funding(held.lease, 60, BUDGET))
                .await
                .expect("fund"),
            FundOutcome::Held(_)
        ));
        let live = relay_id(1);
        assert_eq!(
            store
                .bind(Bind {
                    lease: held.lease,
                    relay_id: &live,
                    fee: 5,
                    slot: 2,
                })
                .await
                .expect("bind"),
            SpendCheck::Accepted
        );
        store.charge_landed(&live, 5).await.expect("charge");
        store
            .release(Release {
                key: &held.lease.key,
                relay_id: &live,
                end: AttemptEnd::Landed { lamports: 15 },
            })
            .await
            .expect("release");
        // The total holds 20 of 100 and the signer holds none of 60.
        assert!(matches!(
            reserve(&store, 2, signer(1), 60).await,
            FundOutcome::Held(_)
        ));
        assert_eq!(
            reserve(&store, 3, signer(2), 21).await,
            FundOutcome::OverTotal
        );
        assert!(matches!(
            reserve(&store, 4, signer(2), 20).await,
            FundOutcome::Held(_)
        ));
    }

    #[tokio::test]
    async fn an_unfunded_row_answers_for_no_budget() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let held = claim(&store, 1, signer(1), 1).await;
        let live = relay_id(1);
        assert_eq!(
            store
                .bind(Bind {
                    lease: held.lease,
                    relay_id: &live,
                    fee: 5,
                    slot: 2,
                })
                .await
                .expect("bind"),
            SpendCheck::Accepted
        );
        store.charge_landed(&live, 5).await.expect("charge");
        store
            .release(Release {
                key: &held.lease.key,
                relay_id: &live,
                end: AttemptEnd::Landed { lamports: 5 },
            })
            .await
            .expect("release");
        assert!(matches!(
            reserve(&store, 2, signer(1), 60).await,
            FundOutcome::Held(_)
        ));
        assert!(matches!(
            reserve(&store, 3, signer(2), 40).await,
            FundOutcome::Held(_)
        ));
    }
}
