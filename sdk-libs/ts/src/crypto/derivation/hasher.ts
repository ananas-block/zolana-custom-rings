const FIELD_BYTES = 32;

/** Rust `pack_be`, 31-byte big-endian chunks with the last one holding the remaining bytes. */
export function packBytesBe(bytes: Uint8Array): Uint8Array[] {
  const fields: Uint8Array[] = [];
  for (let offset = 0; offset < bytes.length; offset += 31) {
    fields.push(packed(bytes.subarray(offset, offset + 31)));
  }
  return fields;
}

function packed(bytes: Uint8Array): Uint8Array {
  const field = new Uint8Array(FIELD_BYTES);
  field.set(bytes, FIELD_BYTES - bytes.length);
  return field;
}
