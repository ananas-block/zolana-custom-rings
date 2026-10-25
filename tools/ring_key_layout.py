"""Filesystem layout for generated ring verifier modules."""

from pathlib import Path


def verifier_relative_path(module: str) -> Path:
    name = module.removesuffix(".rs")
    file = f"{name}.rs"
    if name.startswith("audit_anonymous_entry_"):
        return Path("audit/entry") / file
    if name.startswith("audit_anonymous_"):
        return Path("audit/anonymous") / file
    if name.startswith("audit_"):
        return Path("audit") / file
    if name.startswith("policy_member_"):
        parts = name.split("_")
        if len(parts) < 4 or parts[3] not in {"2", "4", "8", "16"}:
            raise ValueError(f"unknown member policy shape: {module}")
        return Path("policy/member") / f"outputs_{parts[3]}" / file
    if name.startswith("policy_delegate_"):
        return Path("policy/delegate") / file
    if name.startswith("deposit_"):
        return Path("deposit") / file
    if name.startswith("merge_"):
        return Path("merge") / file
    if name.startswith(("apply_records_", "register_key_")):
        return Path("records") / file
    raise ValueError(f"unknown ring verifier family: {module}")
