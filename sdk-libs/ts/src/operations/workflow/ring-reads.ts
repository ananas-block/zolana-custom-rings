/** The policy registries an instruction reads after the ring account, credential trees follow them. */
import type { Address } from "@solana/kit";

import { addressBytes, isZero } from "@heliuslabs/zolana/internal";

import { registryCurator, type RingPolicy } from "../../protocol/codec/ring-codecs.js";

/** Rust `RootRead`, policy roots only, credential roots come from SPP tree accounts. */
export type RootRead = "none" | "own" | "policy";

/** Rust `RootRead::transfer`, a delegate reads no policy root, a restrictive update cannot fail its proof. */
export function transferRootRead(
  config: Pick<RingPolicy, "hasPolicy" | "records">,
  delegate: boolean,
): RootRead {
  if (delegate) return "none";
  if (config.hasPolicy) return "policy";
  return isZeroAddress(config.records) ? "none" : "own";
}

/** Rust `RootRead::deposit`. */
export function depositRootRead(config: Pick<RingPolicy, "hasPolicy">): RootRead {
  return config.hasPolicy ? "policy" : "none";
}

/** Rust `RootRead::merge`, a merge runs no rules. */
export const MERGE_ROOT_READ: RootRead = "none";

/** Rust `RegistrySlots::load`, own and curator by `read`. */
export function ringRegistrySlots(
  config: Pick<RingPolicy, "records" | "sources">,
  read: RootRead,
): readonly Address[] {
  const curator = read === "policy" ? registryCurator(config) : undefined;
  return Object.freeze([
    ...(read === "none" ? [] : [config.records]),
    ...(curator === undefined ? [] : [curator]),
  ]);
}

function isZeroAddress(address: Address): boolean {
  return isZero(addressBytes(address));
}
