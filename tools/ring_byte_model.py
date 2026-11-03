#!/usr/bin/env python3
"""Frame lengths from the serialized size pins, with the extras no pin carries."""

import math
import re
import sys
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SIZE_PINS_PATH = REPOSITORY_ROOT / "sdk-libs/sdk/src/tests/operations/size_pins.rs"

TRANSACTION_LIMIT = 4096
SIGNATURE = 64
ADDRESS = 32
ACCOUNT_INDEX = 1
ACCOUNT = ADDRESS + ACCOUNT_INDEX
CO_SIGNER = SIGNATURE + 2 * ACCOUNT
FIELD = 32
RECIPIENT_BODY = 72
INPUT_COUNT_FIELD_LIMIT = 63
MERGE_WIDTHS = (8, 24, 52)

COLUMN_SLOPES = {
    "Confidential": (97, 168),
    "ConfidentialPolicy": (97, 200),
    "ConfidentialEscrow": (97, 168),
    "InProofOwner": (97, 168),
    "InProofOwnerPolicy": (97, 200),
    "InProofOwnerEscrow": (97, 168),
    "Anonymous": (97, 272),
    "AnonymousPolicy": (97, 272),
    "AnonymousEntry": (169, 272),
    "AnonymousEntryPolicy": (169, 272),
    "Delegate": (97, 168),
}


class Rail(Enum):
    SIGNER = "signer"
    IN_PROOF = "in-proof"
    AUTHORITY = "authority"
    COMMITMENT = "commitment"
    ENTRY = "entry"


class RingMode(Enum):
    AUDIT = "audit"
    PLAIN_POLICY = "plain policy"
    ESCROW = "escrow"


ANONYMOUS_RAILS = (Rail.COMMITMENT, Rail.ENTRY)
KEY_CLASSES = {
    Rail.SIGNER: {2: 24, 4: 24, 8: 16, 16: 5},
    Rail.IN_PROOF: {2: 24, 4: 24, 8: 16, 16: 5},
    Rail.COMMITMENT: {2: 24, 4: 16, 8: 5},
    Rail.ENTRY: {2: 8, 4: 8, 8: 2},
}
CO_OWNER_RAILS = (Rail.SIGNER, Rail.COMMITMENT)

PIN_COLUMNS = {
    (Rail.SIGNER, RingMode.AUDIT): "Confidential",
    (Rail.SIGNER, RingMode.PLAIN_POLICY): "ConfidentialPolicy",
    (Rail.SIGNER, RingMode.ESCROW): "ConfidentialEscrow",
    (Rail.IN_PROOF, RingMode.AUDIT): "InProofOwner",
    (Rail.IN_PROOF, RingMode.PLAIN_POLICY): "InProofOwnerPolicy",
    (Rail.IN_PROOF, RingMode.ESCROW): "InProofOwnerEscrow",
    (Rail.AUTHORITY, RingMode.ESCROW): "Delegate",
    # Anonymous frames always read the records registry, hence the policy pin.
    (Rail.COMMITMENT, RingMode.AUDIT): "AnonymousPolicy",
    (Rail.COMMITMENT, RingMode.PLAIN_POLICY): "AnonymousPolicy",
    (Rail.ENTRY, RingMode.AUDIT): "AnonymousEntryPolicy",
    (Rail.ENTRY, RingMode.PLAIN_POLICY): "AnonymousEntryPolicy",
}


def slot_bits_length(outputs):
    return math.ceil(outputs / 8)


def largest_fitting(counts, frame_at):
    return max(
        (count for count in counts if frame_at(count).length() <= TRANSACTION_LIMIT),
        default=0,
    )


def pin_cell(cell):
    return None if cell == "None" else int(re.fullmatch(r"Some\((\d+)\)", cell).group(1))


class SizePins:
    def __init__(self, source):
        columns_block = re.search(r"const COLUMNS: \[Self; \d+\] = \[(.*?)\];", source, re.DOTALL)
        self.columns = re.findall(r"Self::(\w+)", columns_block.group(1))
        self.rows = {}
        for pin in re.finditer(r"SizePin \{ n_in: (\d+), n_out: (\d+), bytes: \[(.*?)\] \}", source):
            shape = (int(pin.group(1)), int(pin.group(2)))
            cells = [cell.strip() for cell in pin.group(3).split(",")]
            self.rows[shape] = {
                column: pin_cell(cell) for column, cell in zip(self.columns, cells, strict=True)
            }
        declared = int(re.search(r"const SIZE_PINS: \[SizePin; (\d+)\]", source).group(1))
        if len(self.rows) != declared:
            raise ValueError(f"parsed {len(self.rows)} of {declared} size pins")

    def pinned_shapes(self, column):
        return [
            (shape, row[column]) for shape, row in self.rows.items() if row[column] is not None
        ]

    def predict(self, column, inputs, outputs):
        (first_inputs, first_outputs), first_bytes = self.pinned_shapes(column)[0]
        input_slope, output_slope = COLUMN_SLOPES[column]
        return (
            first_bytes
            + input_slope * (inputs - first_inputs)
            + output_slope * (outputs - first_outputs)
            + slot_bits_length(outputs)
            - slot_bits_length(first_outputs)
        )

    def slope_mismatches(self):
        return [
            (column, shape, pinned, self.predict(column, *shape))
            for column in self.columns
            for shape, pinned in self.pinned_shapes(column)
            if pinned != self.predict(column, *shape)
        ]


PINS = SizePins(SIZE_PINS_PATH.read_text())


@dataclass(frozen=True)
class Frame:
    rail: Rail
    mode: RingMode = RingMode.AUDIT
    inputs: int = 1
    outputs: int = 2
    # The owner pays only in the signer pins.
    outsider_payer: bool = True
    co_owners: int = 0
    co_signer: bool = False
    legs: int = 0
    reply_length: int = 0
    change_slots: int = 1
    spl_legs: bool = False
    second_input_tree: bool = False

    def legs_delta(self):
        if not self.legs:
            return 0
        later_legs = self.legs - 1
        # An anonymous exit repeats its destination.
        repeated_destination = self.rail in ANONYMOUS_RAILS
        if not self.spl_legs:
            return 75 + later_legs * (11 if repeated_destination else 43)
        token_owner_field = 0 if self.mode is RingMode.AUDIT else FIELD
        later_leg = 15 if repeated_destination else 47
        return 175 + token_owner_field + later_legs * (later_leg + token_owner_field)

    def reply_delta(self):
        if not self.reply_length:
            return 0
        return 2 + self.reply_length * (self.outputs - self.change_slots)

    def second_tree_delta(self):
        if not self.second_input_tree:
            return 0
        root_indices = 4
        return ACCOUNT + root_indices + slot_bits_length(self.inputs)

    def length(self):
        outsider_signer = SIGNATURE + ADDRESS
        co_owner_signer = SIGNATURE + ACCOUNT
        # The pins carry one change slot.
        change_slot_bodies = RECIPIENT_BODY * (1 - self.change_slots)
        return (
            PINS.predict(PIN_COLUMNS[self.rail, self.mode], self.inputs, self.outputs)
            + (outsider_signer if self.rail is Rail.SIGNER and self.outsider_payer else 0)
            + co_owner_signer * self.co_owners
            + (CO_SIGNER if self.co_signer else 0)
            + self.legs_delta()
            + change_slot_bodies
            + self.reply_delta()
            + self.second_tree_delta()
        )

    def most_inputs(self):
        return largest_fitting(
            range(1, INPUT_COUNT_FIELD_LIMIT + 1), lambda inputs: replace(self, inputs=inputs)
        )

    def most_outputs(self, capacity):
        return largest_fitting(
            range(1, capacity + 1), lambda outputs: replace(self, outputs=outputs)
        )


def merge_disclosure_fields(plaintext_slots):
    return math.ceil(FIELD * plaintext_slots / 31)


@dataclass(frozen=True)
class Merge:
    width: int
    inputs: int = 1
    transmitted_prefix: bool = False
    records_registry: bool = False
    co_signer: bool = False
    second_tree: bool = False

    def length(self):
        version_and_fixed_message = 1 + 3 + 4 + 32 + 1 + 1
        budget_config = 8
        instruction_header = 4
        ring_accounts = 7
        tag_own_revision_ring_data_hash = 1 + 8 + FIELD
        disclosure_head = 192 + 33 + FIELD + 1
        spp_body = 8 + 128 + FIELD + (1 + 16 + 3 * FIELD) + FIELD + 1 + 2 + 2 + 1
        fields = merge_disclosure_fields(self.inputs if self.transmitted_prefix else self.width)
        return (
            version_and_fixed_message
            + budget_config
            + SIGNATURE
            + ADDRESS * ring_accounts
            + instruction_header
            + ACCOUNT_INDEX * ring_accounts
            + tag_own_revision_ring_data_hash
            + disclosure_head
            + FIELD * fields
            + spp_body
            + (FIELD + ACCOUNT) * self.inputs
            + (ACCOUNT if self.records_registry else 0)
            + (CO_SIGNER if self.co_signer else 0)
            + (ADDRESS if self.second_tree else 0)
        )

    def most_inputs(self):
        return largest_fitting(
            range(1, self.width + 1), lambda inputs: replace(self, inputs=inputs)
        )


CONFIDENTIAL_ROWS = [
    ("Signer, owner pays", Frame(Rail.SIGNER, outsider_payer=False)),
    ("Signer, outsider pays", Frame(Rail.SIGNER)),
    ("Signer plain policy, owner pays", Frame(Rail.SIGNER, RingMode.PLAIN_POLICY, outsider_payer=False)),
    ("Signer plain policy, outsider pays", Frame(Rail.SIGNER, RingMode.PLAIN_POLICY)),
    ("Signer escrow, owner pays", Frame(Rail.SIGNER, RingMode.ESCROW, outsider_payer=False)),
    ("Signer escrow, outsider pays", Frame(Rail.SIGNER, RingMode.ESCROW)),
    ("In-proof audit", Frame(Rail.IN_PROOF)),
    ("In-proof plain policy", Frame(Rail.IN_PROOF, RingMode.PLAIN_POLICY)),
    ("In-proof escrow", Frame(Rail.IN_PROOF, RingMode.ESCROW)),
]
LOADED_EXTRAS = {"co_signer": True, "legs": 4}
REPLY_EXTRAS = {"reply_length": 97}
CO_OWNER_EXTRAS = {"co_owners": 1}
MERGE_VARIANTS = [
    ("none", {}),
    ("co-signer", {"co_signer": True}),
    ("escrow registry", {"records_registry": True}),
    ("escrow registry, co-signer", {"records_registry": True, "co_signer": True}),
    (
        "escrow registry, co-signer, second tree",
        {"records_registry": True, "co_signer": True, "second_tree": True},
    ),
]


def byte_cell(length):
    return str(length) if length <= TRANSACTION_LIMIT else f"**{length}**"


def print_table(header, rows):
    print("| " + " | ".join(header) + " |")
    print("|" + "---|" * len(header))
    for row in rows:
        print("| " + " | ".join(str(cell) for cell in row) + " |")
    print()


def print_slope_check(mismatches):
    print(f"Pin mismatches against the slopes: {len(mismatches)}")
    for column, shape, pinned, predicted in mismatches:
        print(f"  {column} {shape[0]}x{shape[1]} pinned {pinned} predicted {predicted}")
    print()


def input_limit_cell(frame):
    variants = [{}, LOADED_EXTRAS]
    if frame.rail in ANONYMOUS_RAILS:
        variants.append(REPLY_EXTRAS)
    if frame.rail in CO_OWNER_RAILS:
        variants.append(CO_OWNER_EXTRAS)
    limits = [replace(frame, **extras).most_inputs() for extras in variants]
    return " / ".join(str(limit) for limit in limits) if any(limits) else "none"


def print_input_limits():
    print(
        "Limits are published counts. Default padding publishes up to the next SPP shape, "
        "only compact padding reaches a count between shapes."
    )
    print()
    print("Published input limit, zero extras / co-signer and 4 legs / one co-owner")
    print_table(
        ["Rail and mode", "2 outputs", "4 outputs", "8 outputs", "16 outputs"],
        [
            [
                name,
                *(input_limit_cell(replace(frame, outputs=outputs)) for outputs in (2, 4, 8, 16)),
            ]
            for name, frame in CONFIDENTIAL_ROWS
        ],
    )
    print("Anonymous, zero extras / co-signer and 4 legs / reply 97 / one co-owner")
    print_table(
        ["Family", "2 outputs", "4 outputs", "8 outputs"],
        [
            [name, *(input_limit_cell(Frame(rail, outputs=outputs)) for outputs in (2, 4, 8))]
            for name, rail in (("Commitment", Rail.COMMITMENT), ("Entry", Rail.ENTRY))
        ],
    )


def print_rail_bytes(title, shapes, rows, extras):
    print(title)
    print_table(
        ["Rail and mode", *(f"{inputs}x{outputs}" for inputs, outputs in shapes)],
        [
            [
                name,
                *(
                    byte_cell(replace(frame, inputs=inputs, outputs=outputs, **extras).length())
                    for inputs, outputs in shapes
                ),
            ]
            for name, frame in rows
        ],
    )


def print_frame_bytes():
    print_rail_bytes(
        "Frame bytes at the provisional classes, zero extras, an over-limit frame in bold",
        ((24, 2), (24, 4), (16, 8), (5, 16), (4, 16)),
        CONFIDENTIAL_ROWS,
        {},
    )
    print_rail_bytes(
        "With a co-signer and 4 legs, outsider payer",
        ((24, 2), (24, 4), (16, 8), (4, 16)),
        [
            (name.removesuffix(", outsider pays"), frame)
            for name, frame in CONFIDENTIAL_ROWS
            if frame.outsider_payer
        ],
        LOADED_EXTRAS,
    )
    print("Anonymous, one change output")
    extras_rows = [
        ("none", {}),
        ("co-signer and 4 legs", LOADED_EXTRAS),
        ("reply 97", REPLY_EXTRAS),
        ("one public co-owner", CO_OWNER_EXTRAS),
    ]
    rows = []
    for name, rail, classes in (
        ("Commitment 24, 16, 5", Rail.COMMITMENT, (24, 16, 5)),
        ("Entry 8, 8, 2", Rail.ENTRY, (8, 8, 2)),
    ):
        for label, extras in extras_rows:
            if extras is CO_OWNER_EXTRAS and rail not in CO_OWNER_RAILS:
                continue
            cells = [
                byte_cell(Frame(rail, inputs=inputs, outputs=outputs, **extras).length())
                for outputs, input_class in zip((2, 4, 8), classes)
                for inputs in (1, input_class)
            ]
            rows.append([name if label == "none" else name.split()[0], label, *cells])
    print_table(
        ["Family", "Extras", "1x2", "class x2", "1x4", "class x4", "1x8", "class x8"], rows
    )
    authority = Frame(Rail.AUTHORITY, RingMode.ESCROW)
    print(
        "Authority: "
        f"2x2 {replace(authority, inputs=2, outputs=2).length()}, "
        f"4x4 {replace(authority, inputs=4, outputs=4).length()}"
    )
    print()
    no_change = Frame(Rail.COMMITMENT, inputs=5, outputs=8, change_slots=0)
    print(f"Anonymous 5x8 with no change output: {no_change.length()}")
    print()


def print_merge_fit():
    print("Merge largest n per extras")
    variant_names = [name for name, _ in MERGE_VARIANTS]
    rows = [
        [
            f"{width}, full list",
            merge_disclosure_fields(width),
            *(Merge(width, **extras).most_inputs() for _, extras in MERGE_VARIANTS),
        ]
        for width in MERGE_WIDTHS
    ]
    widest = MERGE_WIDTHS[-1]
    rows.append(
        [
            f"{widest}, transmitted prefix",
            f"up to {merge_disclosure_fields(widest)}",
            *(
                Merge(widest, transmitted_prefix=True, **extras).most_inputs()
                for _, extras in MERGE_VARIANTS
            ),
        ]
    )
    print_table(["Width", "F", *variant_names], rows)
    print("Merge frame at full width")
    print_table(
        ["Width", *variant_names],
        [
            [
                width,
                *(
                    byte_cell(Merge(width=width, inputs=width, **extras).length())
                    for _, extras in MERGE_VARIANTS
                ),
            ]
            for width in MERGE_WIDTHS
        ],
    )


def print_spl_legs():
    print("SPL legs, bytes of the first leg / each later leg")
    rows = []
    for name, frame in (
        ("Confidential audit", Frame(Rail.SIGNER, legs=1, spl_legs=True)),
        (
            "Confidential plain policy or escrow",
            Frame(Rail.SIGNER, RingMode.ESCROW, legs=1, spl_legs=True),
        ),
        ("Anonymous audit", Frame(Rail.COMMITMENT, legs=1, spl_legs=True)),
        (
            "Anonymous policy",
            Frame(Rail.COMMITMENT, RingMode.PLAIN_POLICY, legs=1, spl_legs=True),
        ),
    ):
        first_leg = frame.legs_delta()
        later_leg = replace(frame, legs=2).legs_delta() - first_leg
        rows.append([name, f"{first_leg} / {later_leg}"])
    print_table(["Rail and mode", "Bytes"], rows)


def print_second_tree_losses():
    print("Frames at their key class one input tree fits and a second does not")
    extras_variants = (
        ("no extras", {}),
        ("co-signer", {"co_signer": True}),
        ("4 legs", {"legs": 4}),
        ("co-signer and 4 legs", LOADED_EXTRAS),
        ("one co-owner", CO_OWNER_EXTRAS),
    )
    rows = []
    for name, frame in (
        *CONFIDENTIAL_ROWS,
        ("Commitment", Frame(Rail.COMMITMENT)),
        ("Entry", Frame(Rail.ENTRY)),
    ):
        for outputs, input_class in KEY_CLASSES[frame.rail].items():
            for label, extras in extras_variants:
                if extras is CO_OWNER_EXTRAS and frame.rail not in CO_OWNER_RAILS:
                    continue
                one_tree = replace(frame, inputs=input_class, outputs=outputs, **extras)
                two_trees = replace(one_tree, second_input_tree=True)
                if one_tree.length() <= TRANSACTION_LIMIT < two_trees.length():
                    rows.append(
                        [
                            name,
                            f"{input_class}x{outputs}",
                            label,
                            one_tree.length(),
                            two_trees.length(),
                        ]
                    )
    print_table(["Rail and mode", "Frame", "Extras", "One tree", "Two trees"], rows)


def print_compact():
    print("Compact, bytes one omitted slot saves")
    saved = {
        name: replace(frame, outputs=3).length() - replace(frame, outputs=2).length()
        for name, frame in (
            ("confidential", Frame(Rail.SIGNER)),
            ("plain policy", Frame(Rail.SIGNER, RingMode.PLAIN_POLICY)),
            ("anonymous", Frame(Rail.COMMITMENT)),
        )
    }
    print(", ".join(f"{name} {length}" for name, length in saved.items()))
    plain = Frame(Rail.SIGNER, RingMode.PLAIN_POLICY)
    print(
        "16 output key under plain policy, largest m: "
        f"1 input owner pays {replace(plain, outsider_payer=False).most_outputs(16)}, "
        f"1 input outsider pays {plain.most_outputs(16)}, "
        f"4 inputs outsider pays {replace(plain, inputs=4).most_outputs(16)}"
    )
    print()


def print_pool_capacity():
    print("Pool capacity")
    public_slots = 3
    rows = []
    for name, keys in (
        ("confidential or commitment 2, w4", [(4, 2, 4)]),
        ("confidential or commitment 2, w32", [(4, 2, 32)]),
        ("confidential or commitment 4, w4", [(4, 4, 4)]),
        ("confidential or commitment 4, w32", [(4, 4, 32)]),
        ("confidential 8, w4", [(4, 8, 4)]),
        ("confidential 8, w32", [(4, 8, 32)]),
        ("confidential 16, w8", [(4, 16, 8)]),
        ("commitment 8, w24", [(4, 8, 24)]),
        ("entry 2, 4, 8, w4", [(1, 2, 4), (1, 4, 4), (1, 8, 4)]),
    ):
        own, curator, today = [], [], []
        for screened, capacity, withdrawals in keys:
            distinct = screened + 2 * capacity + withdrawals
            assets = min(withdrawals, public_slots)
            own.append(distinct + max(assets, public_slots))
            curator.append(distinct + assets)
            today.append(1 + 2 * capacity + withdrawals + public_slots)
        rows.append(
            [name, *(", ".join(str(value) for value in column) for column in (own, curator, today))]
        )
    print_table(["Key", "Own", "Curator", "Own today"], rows)


def main():
    mismatches = PINS.slope_mismatches()
    print_slope_check(mismatches)
    print_input_limits()
    print_frame_bytes()
    print_merge_fit()
    print_compact()
    print_spl_legs()
    print_second_tree_losses()
    print_pool_capacity()
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
