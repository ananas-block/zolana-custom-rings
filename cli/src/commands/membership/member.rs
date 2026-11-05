use anyhow::{bail, Result};
use custom_ring_sdk::enrollment::Enroll;
use solana_signer::Signer;
use spr_interface::pda;
use spr_keypair::ShieldedKeypair;
use zolana_ring_client::{CredentialLookup, CredentialResolver};
use zolana_ring_keys::ListSaltHolder;

use crate::{line, Context, KeyCommand};

const SEAL_PROMPT: &str = "seal the member key to the ring auditor and enroll it?";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    AlreadyEnrolled,
    Enroll,
    Declined,
}

pub fn key(ctx: &Context, command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Register => register_key(ctx),
        KeyCommand::Rotate => crate::viewing_keys::rotate(ctx),
    }
}

fn register_key(ctx: &Context) -> Result<()> {
    let sender = ctx.sender()?;
    let member = ShieldedKeypair::from_keypair(&sender)?;
    line("member", sender.pubkey());
    match plan(enrolled(ctx, &member)?, || ctx.ask_yes(SEAL_PROMPT, true))? {
        Plan::AlreadyEnrolled => line("key", "already enrolled"),
        Plan::Declined => line("key", "not enrolled"),
        Plan::Enroll => {
            enroll(ctx, &member)?;
            line("key", "enrolled");
        }
    }
    Ok(())
}

/// Enrolls each member that holds no credential.
pub(crate) fn enroll_members(ctx: &Context, members: &[&ShieldedKeypair]) -> Result<()> {
    for member in members {
        let outcome = match enrolled(ctx, member)? {
            true => "already enrolled",
            false => {
                enroll(ctx, member)?;
                "enrolled"
            }
        };
        line("member key", format_args!("{} {outcome}", member.pubkey()));
    }
    Ok(())
}

/// An unknown lookup refuses, it never reads as unenrolled.
pub(crate) fn enrolled(ctx: &Context, keys: &ShieldedKeypair) -> Result<bool> {
    let lookup = ctx.block(
        CredentialResolver::new(ctx.ring.program_id(), keys.pubkey())
            .with_nullifier_key(keys.nullifier_key.pubkey()?)
            .resolve(ctx.chain().indexer(), ctx.chain().rpc()),
    )?;
    Ok(match lookup {
        CredentialLookup::Present(_) => true,
        CredentialLookup::Absent(_) => false,
        CredentialLookup::Unknown(reason) => bail!(
            "the credential of {} is unknown ({reason:?}), retry once the indexer serves it",
            keys.pubkey()
        ),
    })
}

fn enroll(ctx: &Context, member: &ShieldedKeypair) -> Result<()> {
    let payer = ctx.funded_authority()?;
    let proven = ctx.block(
        Enroll {
            ring: ctx.ring,
            owner: member.pubkey(),
            payer: payer.pubkey(),
            output_tree: pda::tree(0),
            nullifier_key: &member.nullifier_key,
            list_salt: member.list_salt(&ctx.ring.program_id())?,
            viewing_pubkey: member.viewing_pubkey(),
        }
        .prove(ctx.ring_client()),
    )?;
    let signature = ctx.send(&[payer, member], &proven.instruction.instructions()?)?;
    // A transfer reads the credential through the indexer, it must serve the enrollment first.
    ctx.wait_for_indexed(signature)
}

fn plan(enrolled: bool, confirm: impl FnOnce() -> Result<bool>) -> Result<Plan> {
    Ok(match enrolled {
        true => Plan::AlreadyEnrolled,
        false if confirm()? => Plan::Enroll,
        false => Plan::Declined,
    })
}
