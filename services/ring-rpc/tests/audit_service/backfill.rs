use super::*;

#[tokio::test]
async fn a_backfill_fills_the_store_before_any_page_read() {
    let fixture = Fixture::new();
    let utxos = SpentUtxo::new(&fixture);
    let mut source = utxos.source(
        &fixture,
        [
            (None, paged(vec![utxos.paid.clone()], Some(1), None)),
            (Some(vec![1]), paged(Vec::new(), None, Some(2))),
        ],
    );
    source.pages.insert(
        Some(vec![9]),
        paged(vec![utxos.spent.clone()], None, Some(10)),
    );
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let found = service
        .audited_utxos(&utxos_request(vec![utxos.commitment.into()]))
        .await
        .expect("UTXO read");
    let [Some(view)] = found.value.utxos.as_slice() else {
        panic!("the backfill opened the paid UTXO, {:?}", found.value.utxos);
    };
    assert_eq!(found.context.slot, 99);
    assert_eq!(
        (view.utxo.amount, view.utxo.owner_key.0.to_bytes()),
        (utxos.member.amount, utxos.member.owner_key)
    );
    assert_eq!(view.tx_signature.0, utxos.paid.tx_signature);
    assert_eq!(
        input_ring(&read_at(&service, Some(9)).await),
        Some(DecryptedInputRing::Ring {
            commitment: utxos.commitment.into(),
        })
    );
}

#[tokio::test]
async fn a_backfill_opens_a_deposited_utxo_a_later_spend_names() {
    let fixture = Fixture::new();
    let member = sol(0xa6, 64);
    let blinding = field(0x66);
    let (deposit, bindings) = audited_deposit(&fixture.auditor.pubkey(), &member, blinding);
    let commitment = deposit.output_slots[0].output_context.hash;
    let exit = [Output::Exit(sol(0xe9, 64)), Output::Dummy];
    let spent = Indexed {
        transfer: &ring_transfer(83),
        outputs: &exit,
        auditor: &fixture.auditor.pubkey(),
        signature: 83,
        frames: &fixture.frames,
    }
    .anonymous_commitments(&[Some(commitment)]);
    let mut source = fixture
        .source()
        .with_transactions(vec![deposit.clone(), spent.clone()]);
    source.configs.get_mut(&RING).expect("config").mode = RingMode::Anonymous;
    source.deposits.insert(deposit.tx_signature, bindings);
    source.pages = HashMap::from([
        (None, paged(vec![deposit, spent.clone()], Some(1), None)),
        (Some(vec![1]), paged(Vec::new(), None, Some(2))),
        (Some(vec![9]), paged(vec![spent], None, Some(10))),
    ]);
    let service = fixture.hub(source).service(None).expect("service");
    let before = read_at(&service, Some(9)).await;
    assert!(before.value.skipped.is_empty());
    let [unresolved] = before.value.items.as_slice() else {
        panic!("the spend opens before its deposit");
    };
    assert_eq!(unresolved.sender, None);
    assert!(unresolved.inputs[0].unseen);
    assert_eq!(unresolved.inputs[0].hash, Some(commitment.into()));
    assert_eq!(amounts(unresolved), [64]);
    service.backfill_utxos().await.expect("backfill");
    let found = service
        .audited_utxos(&utxos_request(vec![commitment.into()]))
        .await
        .expect("UTXO read");
    let [Some(view)] = found.value.utxos.as_slice() else {
        panic!("the backfill opened the deposit, {:?}", found.value.utxos);
    };
    assert_eq!(
        (view.utxo.amount, view.utxo.nullifier_pk.clone()),
        (64, None)
    );
    let after = read_at(&service, Some(9)).await;
    assert_eq!(
        input_ring(&after),
        Some(DecryptedInputRing::Ring {
            commitment: commitment.into(),
        })
    );
    assert_eq!(
        after.value.items[0].sender.as_ref().unwrap().nullifier_pk,
        None
    );
}

#[tokio::test]
async fn audited_utxos_answer_in_request_order_with_null_for_an_unseen_hash() {
    let fixture = Fixture::new();
    let hub = Arc::new(fixture.hub(fixture.source()));
    let service = hub.service(None).expect("service");
    read_at(&service, None).await;
    let outputs: Vec<[u8; 32]> = fixture
        .audited
        .output_slots
        .iter()
        .map(|slot| slot.output_context.hash)
        .collect();
    let unseen = Hash([0x77; 32]);
    let request = utxos_request(vec![outputs[1].into(), unseen, outputs[0].into()]);
    let module = rpc_module(hub).expect("module");
    let response: GetAuditedUtxosResponse = module
        .call(GET_AUDITED_UTXOS, as_object(&request))
        .await
        .expect("UTXO read");
    let amounts: Vec<Option<u64>> = response
        .value
        .utxos
        .iter()
        .map(|view| view.as_ref().map(|view| view.utxo.amount))
        .collect();
    assert_eq!(amounts, [Some(7), None, Some(500)]);
    // A page read opens UTXOs, only the backfill vouches for the history before its context.
    assert_eq!(response.context.slot, 0);
    let wire = as_object(response.value.utxos[0].as_ref().expect("opened UTXO"));
    let keys: HashSet<&str> = wire.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        HashSet::from([
            "utxoHash",
            "utxo",
            "slot",
            "txSignature",
            "eventIndex",
            "slotIndex",
        ])
    );
    assert_eq!(
        wire["utxoHash"],
        serde_json::json!(Hash(outputs[1]).to_base58())
    );
    assert_eq!(wire["slotIndex"], serde_json::json!(1));
}

#[tokio::test]
async fn audited_utxos_refuse_an_ungranted_reader_a_bad_count_a_changed_hash_and_a_replay() {
    let fixture = Fixture::new();
    let service = fixture
        .hub(fixture.source())
        .service(None)
        .expect("service");
    let hashes = vec![Hash([0x77; 32])];
    let stranger_request = GetAuditedUtxosRequest::read(target(RING), hashes.clone())
        .expect("UTXO read")
        .sign(&stranger())
        .expect("signed UTXO read");
    assert!(matches!(
        service.audited_utxos(&stranger_request).await,
        Err(RingRpcError::Unauthorized(Unauthorized::NotGranted))
    ));
    for count in [0, AUDITED_UTXOS_LIMIT + 1] {
        let hashes = vec![Hash([0x77; 32]); count];
        assert!(matches!(
            GetAuditedUtxosRequest::read(target(RING), hashes.clone()),
            Err(ReadBuildError::UtxoHashes)
        ));
        let request = GetAuditedUtxosRequest {
            utxo_hashes: hashes,
            ..utxos_request(vec![Hash([0x77; 32])])
        };
        assert!(matches!(
            service.audited_utxos(&request).await,
            Err(RingRpcError::InvalidUtxoRequest)
        ));
    }
    let mut changed = utxos_request(hashes.clone());
    changed.utxo_hashes = vec![Hash([0x78; 32])];
    assert!(matches!(
        service.audited_utxos(&changed).await,
        Err(RingRpcError::Unauthorized(Unauthorized::BadSignature))
    ));
    let request = utxos_request(hashes);
    assert!(service.audited_utxos(&request).await.is_ok());
    assert!(matches!(
        service.audited_utxos(&request).await,
        Err(RingRpcError::Unauthorized(Unauthorized::Replay))
    ));
}

#[tokio::test]
async fn an_escrowed_ring_opens_its_outputs_with_the_keys_its_registry_holds() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let page = read_at(&service, None).await;
    let [item] = page.value.items.as_slice() else {
        panic!("one escrowed transfer, {:?}", page.value.skipped);
    };
    assert!(item.payload_errors.is_empty(), "{:?}", item.payload_errors);
    assert_eq!(amounts(item), [30, 12]);
    let keys: Vec<Hash> = item
        .outputs
        .iter()
        .map(|output| output.utxo.as_ref().expect("utxo").nullifier_pk.clone())
        .collect();
    assert_eq!(keys, owners.map(|utxo| Hash(utxo.nullifier_pk)));
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_read_never_reads_the_registry() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let page = read_at(&service, None).await;
    assert_eq!(escrow_pending(&page).len(), 2);
    assert_eq!(record_reads.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn concurrent_backfills_read_the_registry_once() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30)];
    let source = escrowed_source(&fixture, &owners, &owners);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let (first, second) = tokio::join!(service.backfill_utxos(), service.backfill_utxos());
    first.expect("first backfill");
    second.expect("second backfill");
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_moved_records_root_rereads_the_records() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners[..1]);
    let records = source.records.clone();
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(escrow_pending(&read_at(&service, None).await).len(), 1);

    records.escrow(&escrow_writes(&owners[1..]));
    service.backfill_utxos().await.expect("backfill");
    assert!(escrow_pending(&read_at(&service, None).await).is_empty());
    assert_eq!(record_reads.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn an_owner_the_registry_never_escrowed_keeps_its_proven_fields() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners[..1]);
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let page = read_at(&service, None).await;
    let [item] = page.value.items.as_slice() else {
        panic!("one escrowed transfer, {:?}", page.value.skipped);
    };
    assert_eq!(amounts(item), [30]);
    assert!(item.payload_errors.is_empty());
    let pending = &item.outputs[1];
    assert_eq!(pending.kind, DecryptedOutputKind::EscrowPending);
    assert_eq!(pending.recipient_u, Some(fixture.recipient_u.into()));
    let fields = pending.escrow_pending.as_ref().expect("proven fields");
    assert_eq!(fields.owner_key, owners[1].owner_key.into());
    assert_eq!((fields.amount, fields.asset.as_ref()), (12, None));
}

/// A page short of a record keeps no partial key map, the next backfill reads again.
#[tokio::test]
async fn a_registry_page_short_of_a_record_escrows_no_key() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners);
    source.records.shorten_pages();
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(escrow_pending(&read_at(&service, None).await).len(), 2);
    let refreshed = record_reads.load(Ordering::Relaxed);
    service.backfill_utxos().await.expect("backfill");
    assert!(record_reads.load(Ordering::Relaxed) > refreshed);
}

#[tokio::test]
async fn the_backfill_reads_the_escrowed_keys_before_its_first_page() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30)];
    let mut source = escrowed_source(&fixture, &owners, &owners);
    let audited = source.transactions.clone();
    source.pages = HashMap::from([(None, paged(audited, None, Some(1)))]);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
    let hash = fixture_output_hash(&service, &owners[0]).await;
    let found = service
        .audited_utxos(&utxos_request(vec![hash]))
        .await
        .expect("UTXO read");
    assert_eq!(
        found.value.utxos[0].as_ref().map(|view| view.utxo.amount),
        Some(30)
    );
}

#[tokio::test]
async fn confirmed_deposit_and_merge_tag_collisions_do_not_poison_an_audit_page() {
    let fixture = Fixture::new();
    let mut deposit = fixture.missing_message.clone();
    deposit.tx_signature = Signature::from([11; 64]);
    deposit.proofless = true;
    deposit.tx_viewing_pk = None;
    deposit.nullifiers.clear();
    let mut merge = fixture.missing_message.clone();
    merge.tx_signature = Signature::from([12; 64]);
    merge.tx_viewing_pk = None;
    let source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone(), deposit, merge]);
    let service = fixture.hub(source).service(None).unwrap();
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &auth(&delegate()),
            page: &page(),
            wallet: None,
        })
        .await
        .unwrap();
    assert_eq!(response.value.items.len(), 1);
    assert_eq!(
        response.value.items[0].tx_signature,
        fixture.audited.tx_signature.into()
    );
    assert!(response.value.skipped.is_empty());
}

#[tokio::test]
async fn recipient_bodies_cannot_poison_an_audit_page_or_trigger_registry_refresh() {
    let fixture = Fixture::new();
    let auditor = fixture.auditor.pubkey();
    let outputs: Vec<Output> = (0u8..6)
        .map(|k| paid(sol(0xb0 + k, 10 + u64::from(k)), x25519_u(0x40 + k)))
        .chain([Output::Dummy, Output::Dummy])
        .collect();
    let delivered = |seed: u8| {
        Indexed {
            transfer: &ring_transfer(seed),
            outputs: &outputs,
            auditor: &auditor,
            signature: seed,
            frames: &fixture.frames,
        }
        .delivered()
    };
    // The body is a stream cipher, a flipped bit changes the amount the commitment binds.
    let mut corrupted = delivered(8);
    *corrupted.output_slots[1]
        .payload
        .last_mut()
        .expect("delivered body") ^= 1;
    // A body that opens under its slot secret yet rebuilds no asset's commitment.
    let mut unmatched = delivered(9);
    let transfer = ring_transfer(9);
    let secret = transfer.delivered_secret(&x25519_u(0x42), 2);
    let body = seal_delivered_body(
        &DeliveredBody {
            blinding: transfer.blinding(2),
            amount: 13,
            owner_key: [0x13; 32],
            nullifier_pk: Some(field(0x13)),
        },
        &secret,
    )
    .expect("delivered body");
    unmatched.output_slots[2].payload = encode_ring_confidential_delivered_output(&body).unwrap();
    let mut invalid_disclosure = delivered(10);
    // The envelope's first byte, past the tagged ephemeral key.
    invalid_disclosure.messages[0].data[33] ^= 1;
    let source = fixture
        .source()
        .with_transactions(vec![corrupted, unmatched, invalid_disclosure]);
    *source.assets.lock().unwrap() = None;
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).unwrap();
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &auth(&delegate()),
            page: &page(),
            wallet: None,
        })
        .await
        .unwrap();
    assert_eq!(response.value.items.len(), 2);
    for (item, slot_index) in response.value.items.iter().zip([1, 2]) {
        assert_eq!(item.outputs.len(), outputs.len() - 1);
        assert_eq!(
            item.payload_errors,
            [DecryptedPayloadError {
                slot_index,
                kind: OutputPayloadErrorKind::UnknownAsset,
            }]
        );
    }
    assert_eq!(response.value.skipped.len(), 1);
    assert_eq!(
        response.value.skipped[0].reason,
        SkippedReason::InvalidAuditData
    );
    // One read at the page start, the miss floor holds back a read per poisoned slot.
    assert_eq!(reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn unknown_assets_share_refresh_and_back_off_after_failure() {
    const ASSET_ID: u64 = 2;
    let asset = Address::new_from_array([8; 32]);
    let fixture = Fixture::new();
    let source = fixture.source().with_transactions(vec![Indexed {
        transfer: &ring_transfer(8),
        outputs: &[Output::Exit(utxo(0xb8, asset, 13))],
        auditor: &fixture.auditor.pubkey(),
        signature: 8,
        frames: &fixture.frames,
    }
    .delivered()]);
    *source.assets.lock().unwrap() =
        Some(RingAssets::new([Mint::new(asset, ASSET_ID)]).expect("ring assets"));
    let unknown_transactions = source.transactions.clone();
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let ed25519 = auth(&delegate());
    let p256 = auth(&Passkey::new(46));
    let (first, second) = tokio::join!(
        service.read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &ed25519,
            page: &page,
            wallet: None,
        }),
        service.read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &p256,
            page: &page,
            wallet: None,
        })
    );
    let mint = |response: &GetDecryptedTransactionsResponse| {
        let utxo = response.value.items[0].outputs[0].utxo.as_ref();
        utxo.and_then(|utxo| utxo.mint.as_ref()).map(|mint| mint.0)
    };
    for result in [first, second] {
        assert_eq!(mint(&result.expect("refreshed read")), Some(asset));
    }
    assert_eq!(reads.load(Ordering::Relaxed), 1);

    let source = fixture
        .source()
        .with_transactions(unknown_transactions.clone());
    *source.assets.lock().unwrap() = None;
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    for signer in [&delegate() as &dyn ReadSigner, &Passkey::new(46)] {
        let response = service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &auth(signer),
                page: &page,
                wallet: None,
            })
            .await
            .unwrap();
        assert_eq!(response.value.items[0].outputs.len(), 2);
        assert_eq!(mint(&response), None);
        assert!(response.value.skipped.is_empty());
    }
    assert_eq!(reads.load(Ordering::Relaxed), 1);

    let mut source = fixture.source().with_transactions(unknown_transactions);
    source.asset_delay = Some(Duration::from_secs(1));
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let first = auth(&delegate());
    assert!(tokio::time::timeout(
        Duration::from_millis(1),
        service.read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &first,
            page: &page,
            wallet: None,
        })
    )
    .await
    .is_err());
    let second = auth(&Passkey::new(46));
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &second,
            page: &page,
            wallet: None,
        })
        .await
        .unwrap();
    assert_eq!(mint(&response), None);
    assert!(response.value.skipped.is_empty());
    assert_eq!(reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_backfill_stops_at_its_page_budget() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = long_history(&fixture, None, 1);
    let reads = source.history_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("bounded backfill");
    assert!(reads.load(Ordering::Relaxed) < HISTORY_READ_CAP);
}

#[tokio::test]
async fn the_utxo_context_moves_only_at_the_scan_frontier() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = HashMap::from([
        (None, paged(vec![fixture.audited.clone()], Some(1), None)),
        (
            Some(vec![1]),
            paged(vec![outside_row(&fixture)], Some(1), None),
        ),
    ]);
    let service = fixture.hub(source).service(None).expect("service");
    assert!(matches!(
        service.backfill_utxos().await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));
    let hash = Hash(fixture.audited.output_slots[0].output_context.hash);
    let found = service
        .audited_utxos(&utxos_request(vec![hash]))
        .await
        .expect("UTXO read");
    assert!(found.value.utxos[0].is_some());
    assert_eq!(found.context.slot, 0);
}

#[tokio::test]
async fn an_unconfigured_ring_backfills_nothing() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.configs.clear();
    let reads = source.history_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("unconfigured ring");
    assert_eq!(reads.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_row_whose_origin_does_not_decode_is_skipped_and_the_backfill_goes_past_it() {
    let fixture = Fixture::new();
    let utxos = SpentUtxo::new(&fixture);
    let rows = vec![utxos.entry.clone(), utxos.paid.clone()];
    let mut source = utxos.source(
        &fixture,
        [
            (None, paged(rows, Some(1), None)),
            (Some(vec![1]), paged(Vec::new(), None, Some(2))),
        ],
    );
    source.undecodable.insert(utxos.entry.tx_signature);
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let found = service
        .audited_utxos(&utxos_request(vec![utxos.commitment.into()]))
        .await
        .expect("UTXO read");
    assert!(found.value.utxos[0].is_some(), "the row after the bad one");
    let page = read_at(&service, None).await;
    let [skipped] = page.value.skipped.as_slice() else {
        panic!("one bad row, {:?}", page.value.skipped);
    };
    assert_eq!(skipped.tx_signature.0, utxos.entry.tx_signature);
    assert_eq!(skipped.reason, SkippedReason::InvalidAuditData);
    assert_eq!(page.value.items.len(), 1);
}

#[tokio::test]
async fn a_failed_origin_read_stops_the_backfill_at_its_position() {
    let fixture = Fixture::new();
    let utxos = SpentUtxo::new(&fixture);
    let mut source = utxos.source(
        &fixture,
        [
            (None, paged(vec![utxos.paid.clone()], None, Some(1))),
            (Some(vec![1]), paged(Vec::new(), None, Some(1))),
        ],
    );
    source.origins.clear();
    let service = fixture.hub(source).service(None).expect("service");
    assert!(service.backfill_utxos().await.is_err());
    assert!(read_at_result(&service, None).await.is_err());
}

#[tokio::test(start_paused = true)]
async fn a_mint_registered_inside_the_refresh_interval_opens_on_a_miss() {
    let fixture = Fixture::new();
    let fresh = Address::new_from_array([0xee; 32]);
    let outputs = [
        paid(utxo(0xb4, fresh, 40), fixture.recipient_u),
        Output::Dummy,
    ];
    let transaction = Indexed {
        transfer: &ring_transfer(84),
        outputs: &outputs,
        auditor: &fixture.auditor.pubkey(),
        signature: 84,
        frames: &fixture.frames,
    }
    .delivered_with(false);
    let source = fixture.source().with_transactions(vec![transaction]);
    let registry = source.assets.clone();
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let first = read_at(&service, None).await;
    assert_eq!(
        first.value.items[0].payload_errors,
        [DecryptedPayloadError {
            slot_index: 0,
            kind: OutputPayloadErrorKind::UnknownAsset,
        }]
    );
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    // A slot no registration names misses on every read, the floor holds the registry reads.
    read_at(&service, None).await;
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    *registry.lock().unwrap() = Some(RingAssets::new([Mint::new(fresh, 9)]).expect("assets"));
    tokio::time::advance(Duration::from_secs(5)).await;
    let second = read_at(&service, None).await;
    assert_eq!(reads.load(Ordering::Relaxed), 2);
    assert!(second.value.items[0].payload_errors.is_empty());
    assert_eq!(amounts(&second.value.items[0]), [40]);
}

fn held_output(
    fixture: &Fixture,
    owners: &[UtxoFields],
    registered: &[UtxoFields],
) -> (StaticSource, Hash) {
    let source = escrowed_source(fixture, owners, registered);
    let hash = Hash(source.transactions[0].output_slots[0].output_context.hash);
    (source, hash)
}

async fn stored_amount(service: &AuditService<StaticSource>, hash: &Hash) -> Option<u64> {
    let found = service
        .audited_utxos(&utxos_request(vec![hash.clone()]))
        .await
        .expect("UTXO read");
    found.value.utxos[0].as_ref().map(|view| view.utxo.amount)
}

fn cursors(source: &StaticSource) -> Vec<Option<Vec<u8>>> {
    source.history_cursors.lock().unwrap().clone()
}

#[tokio::test]
async fn an_escrow_refresh_failure_then_recovery_stores_the_output_with_no_rescan() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30)];
    let (source, hash) = held_output(&fixture, &owners, &owners);
    source.records_down.store(true, Ordering::Relaxed);
    let down = source.records_down.clone();
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(stored_amount(&service, &hash).await, None);

    down.store(false, Ordering::Relaxed);
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(stored_amount(&service, &hash).await, Some(30));
    assert_eq!(cursors(&probe), [None, Some(vec![1])]);
}

#[tokio::test(start_paused = true)]
async fn an_unknown_mint_then_registration_stores_the_output_with_no_rescan() {
    let fixture = Fixture::new();
    let fresh = Address::new_from_array([0xee; 32]);
    let outputs = [
        paid(utxo(0xb4, fresh, 40), fixture.recipient_u),
        Output::Dummy,
    ];
    let transaction = Indexed {
        transfer: &ring_transfer(84),
        outputs: &outputs,
        auditor: &fixture.auditor.pubkey(),
        signature: 84,
        frames: &fixture.frames,
    }
    .delivered_with(false);
    let hash = Hash(transaction.output_slots[0].output_context.hash);
    let mut source = fixture
        .source()
        .with_transactions(vec![transaction.clone()]);
    source.pages = HashMap::from([
        (None, paged(vec![transaction], None, Some(1))),
        (Some(vec![1]), paged(Vec::new(), None, Some(1))),
    ]);
    let registry = source.assets.clone();
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(stored_amount(&service, &hash).await, None);

    *registry.lock().unwrap() = Some(RingAssets::new([Mint::new(fresh, 9)]).expect("assets"));
    tokio::time::advance(Duration::from_secs(60)).await;
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(stored_amount(&service, &hash).await, Some(40));
    let found = service
        .audited_utxos(&utxos_request(vec![hash]))
        .await
        .expect("UTXO read");
    let view = found.value.utxos[0].as_ref().expect("stored output");
    assert_eq!(view.utxo.mint.as_ref().map(|mint| mint.0), Some(fresh));
    assert_eq!(cursors(&probe), [None, Some(vec![1])]);
}

#[tokio::test]
async fn a_restart_keeps_a_row_its_dependency_left_open() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30)];
    let (source, hash) = held_output(&fixture, &owners, &owners);
    source.records_down.store(true, Ordering::Relaxed);
    let down = source.records_down.clone();
    let probe = source.clone();
    let before = fixture.hub(source.clone()).service(None).expect("service");
    before.backfill_utxos().await.expect("backfill");
    assert_eq!(stored_amount(&before, &hash).await, None);

    let restarted = fixture.hub(source).service(None).expect("service");
    restarted.backfill_utxos().await.expect("backfill");
    assert_eq!(stored_amount(&restarted, &hash).await, None);
    down.store(false, Ordering::Relaxed);
    restarted.backfill_utxos().await.expect("backfill");
    assert_eq!(stored_amount(&restarted, &hash).await, Some(30));
    assert_eq!(cursors(&probe), [None, None, Some(vec![1])]);
}

#[tokio::test]
async fn a_permanently_invalid_row_passes_the_cursor() {
    let fixture = Fixture::new();
    let rows = vec![fixture.foreign_key.clone(), fixture.audited.clone()];
    let hash = Hash(fixture.audited.output_slots[0].output_context.hash);
    let mut source = fixture.source().with_transactions(rows.clone());
    source.pages = HashMap::from([
        (None, paged(rows, None, Some(1))),
        (Some(vec![1]), paged(Vec::new(), None, Some(1))),
    ]);
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(stored_amount(&service, &hash).await, Some(500));
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(cursors(&probe), [None, Some(vec![1])]);
}

#[tokio::test]
async fn a_lost_auditor_message_holds_the_backfill_and_lists_on_a_read() {
    let fixture = Fixture::new();
    let rows = vec![fixture.missing_message.clone(), fixture.audited.clone()];
    let mut source = fixture.source().with_transactions(rows.clone());
    source.pages = HashMap::from([(None, paged(rows, None, Some(1)))]);
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    assert!(service.backfill_utxos().await.is_err());
    assert!(service.backfill_utxos().await.is_err());
    assert_eq!(cursors(&probe), [None, None]);
    let page = read_at(&service, None).await;
    let [skipped] = page.value.skipped.as_slice() else {
        panic!("one lost message, {:?}", page.value.skipped);
    };
    assert_eq!(skipped.reason, SkippedReason::MissingAuditorMessage);
    assert_eq!(page.value.items.len(), 1);
}

#[tokio::test]
async fn a_faulty_call_stack_stops_the_backfill_and_the_read() {
    let fixture = Fixture::new();
    let rows = vec![fixture.audited.clone()];
    let mut source = fixture.source().with_transactions(rows.clone());
    source.pages = HashMap::from([(None, paged(rows, None, Some(1)))]);
    source.stack_faults.insert(fixture.audited.tx_signature);
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    assert!(service.backfill_utxos().await.is_err());
    assert!(service.backfill_utxos().await.is_err());
    assert_eq!(cursors(&probe), [None, None]);
    assert!(read_at_result(&service, None).await.is_err());
}

#[tokio::test]
async fn a_replaced_registry_replaces_the_escrowed_keys() {
    let fixture = Fixture::new();
    let owner_a = sol(0xc0, 30);
    let owner_b = sol(0xc1, 12);
    let other = sol(0xc2, 1);
    let source = escrowed_source(&fixture, &[owner_a, owner_b], &[owner_a, other]);
    let record_reads = source.record_reads.clone();
    let probe = source.clone();
    let hash_b = Hash(source.transactions[0].output_slots[1].output_context.hash);
    let hash_a = Hash(source.transactions[0].output_slots[0].output_context.hash);
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(stored_amount(&service, &hash_a).await, Some(30));
    assert_eq!(stored_amount(&service, &hash_b).await, None);
    let revision_a = probe.records.root().revision;
    let reads = record_reads.load(Ordering::Relaxed);

    let replacement = Records::listing(&[
        reader_member(ReaderKey::ed25519(delegate().pubkey()).expect("delegate reader")),
        reader_member(ReaderKey::p256(Passkey::new(46).pubkey()).expect("passkey reader")),
    ]);
    replacement.escrow(&escrow_writes(&[owner_b]));
    assert!(replacement.root().revision < revision_a);
    probe.records.replace_with(replacement);
    *probe.registry.lock().unwrap() = Address::new_from_array([12; 32]);
    service.backfill_utxos().await.expect("backfill");
    assert!(record_reads.load(Ordering::Relaxed) > reads);
    assert_eq!(stored_amount(&service, &hash_b).await, Some(12));
    let page = read_at(&service, None).await;
    let pending = escrow_pending(&page);
    let [pending] = pending.as_slice() else {
        panic!("registry A's owner lost its key, {pending:?}");
    };
    assert_eq!(pending.owner_key, owner_a.owner_key.into());
}

/// A row of no served ring, each pass reads it and applies nothing.
fn outside_row(fixture: &Fixture) -> ShieldedTransaction {
    let mut row = fixture.audited.clone();
    row.ring_program_id = None;
    row
}

/// More non terminal pages than one pass reads, from `start`, keyed from `first`.
fn long_history(
    fixture: &Fixture,
    start: Option<Vec<u8>>,
    first: u8,
) -> HashMap<Option<Vec<u8>>, Paged> {
    let mut pages = HashMap::new();
    let mut key = start;
    for index in first..first + 70 {
        pages.insert(
            key.clone(),
            paged(vec![outside_row(fixture)], Some(index), None),
        );
        key = Some(vec![index]);
    }
    pages.insert(key, paged(Vec::new(), None, Some(200)));
    pages
}

async fn coverage(service: &AuditService<StaticSource>) -> Coverage {
    let request = UnspentUtxosRequest::new(target(RING), [1; 32])
        .sign(&delegate())
        .expect("signed unspent read");
    service
        .unspent_utxos(&request)
        .await
        .expect("unspent read")
        .coverage
}

#[tokio::test]
async fn an_empty_history_covers_only_its_terminal_slot() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = HashMap::from([(None, paged(Vec::new(), None, Some(1)))]);
    let service = fixture.hub(source).service(None).expect("service");
    assert!(!coverage(&service).await.complete, "no pass reached a page");
    service.backfill_utxos().await.expect("backfill");
    let covered = coverage(&service).await;
    assert_eq!(
        (covered.from_slot, covered.through_slot, covered.complete),
        (99, 99, true)
    );
}

#[tokio::test]
async fn a_partial_pass_drops_complete_until_a_later_terminal_page() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = long_history(&fixture, Some(vec![1]), 2);
    source.pages.insert(None, paged(Vec::new(), None, Some(1)));
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("first pass");
    let first = coverage(&service).await;
    assert!(first.complete);

    service.backfill_utxos().await.expect("capped pass");
    let capped = coverage(&service).await;
    assert!(!capped.complete, "the cap stopped the pass");
    assert_eq!(capped.through_slot, first.through_slot);

    service.backfill_utxos().await.expect("last pass");
    let last = coverage(&service).await;
    assert!(last.complete);
    assert!(last.through_slot > first.through_slot);
}

#[tokio::test]
async fn a_failure_after_a_successful_scan_drops_complete_until_a_retry_passes() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = HashMap::from([(None, paged(Vec::new(), None, Some(1)))]);
    let down = source.history_down.clone();
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("first pass");
    let through = coverage(&service).await.through_slot;

    down.store(true, Ordering::Relaxed);
    assert!(service.backfill_utxos().await.is_err());
    let failed = coverage(&service).await;
    assert_eq!((failed.complete, failed.through_slot), (false, through));

    down.store(false, Ordering::Relaxed);
    service.backfill_utxos().await.expect("retry");
    assert!(coverage(&service).await.complete);
    assert_eq!(cursors(&probe), [None, Some(vec![1]), Some(vec![1])]);
}

#[tokio::test]
async fn a_snapshot_behind_the_floor_refuses_the_page_and_keeps_the_position() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = HashMap::from([(None, paged(Vec::new(), None, Some(1)))]);
    let context = source.forced_context.clone();
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("first pass");
    let through = coverage(&service).await.through_slot;

    *context.lock().unwrap() = Some(through - 1);
    assert!(matches!(
        service.backfill_utxos().await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));
    let behind = coverage(&service).await;
    assert_eq!((behind.complete, behind.through_slot), (false, through));

    *context.lock().unwrap() = None;
    service.backfill_utxos().await.expect("caught up");
    assert!(coverage(&service).await.complete);
    assert_eq!(cursors(&probe), [None, Some(vec![1]), Some(vec![1])]);
}

#[tokio::test]
async fn a_retryable_row_keeps_the_position_and_complete_false() {
    let fixture = Fixture::new();
    let rows = vec![fixture.missing_message.clone(), fixture.audited.clone()];
    let mut source = fixture.source().with_transactions(rows.clone());
    source.pages = HashMap::from([(None, paged(rows, None, Some(1)))]);
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    assert!(service.backfill_utxos().await.is_err());
    assert!(service.backfill_utxos().await.is_err());
    assert_eq!(cursors(&probe), [None, None]);
    assert!(!coverage(&service).await.complete);
}

#[tokio::test]
async fn a_restart_replays_from_the_start_and_claims_nothing_until_it_ends() {
    let fixture = Fixture::new();
    let rows = vec![fixture.audited.clone()];
    let hash = Hash(fixture.audited.output_slots[0].output_context.hash);
    let mut source = fixture.source().with_transactions(rows.clone());
    source.pages = HashMap::from([(None, paged(rows, None, Some(1)))]);
    let probe = source.clone();
    let before = fixture.hub(source.clone()).service(None).expect("service");
    before.backfill_utxos().await.expect("first run");
    assert!(coverage(&before).await.complete);

    let restarted = fixture.hub(source).service(None).expect("service");
    assert!(
        !coverage(&restarted).await.complete,
        "the replay has not run"
    );
    restarted.backfill_utxos().await.expect("replay");
    assert!(coverage(&restarted).await.complete);
    assert_eq!(
        stored_amount(&restarted, &hash).await,
        stored_amount(&before, &hash).await
    );
    assert_eq!(cursors(&probe), [None, None]);
}
