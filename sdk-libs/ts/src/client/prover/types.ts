import type { RecordOpening } from "../../interface/member-registry.js";

export { RING_DEPOSIT_AUDIT_SLOTS } from "../../interface/ring-deposit-capsule.js";

/** Rust `MAX_RULES` and `MAX_INLINE_ASSETS`, the fixed rule table width. */
export const RING_RULE_SLOTS = 16;
export const RING_INLINE_ASSET_SLOTS = 8;
/** Rust `MAX_SOURCES`, the positional source map width. */
export const RING_SOURCE_SLOTS = 8;
/** Rust `MAX_OUTFLOW_LIMITS`, one bound per mint a table limits. */
export const RING_OUTFLOW_LIMIT_SLOTS = 8;
export const RING_STATE_PATH_LENGTH = 32;

/** Rust `ANONYMOUS_MERGE_WIDTHS`, the merge widths whose disclosure still fits one v1 transaction. */
export const ANONYMOUS_MERGE_WIDTHS: readonly number[] = Object.freeze([8, 24]);

/** A member's record in a member registry, the opening a ring merge proves. */
export type PresentRecordOpening = Extract<RecordOpening, { kind: "present" }>;
