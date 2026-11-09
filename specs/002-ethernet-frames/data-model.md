# Data model: Ethernet frame views and frame building

## TagKind

| Variant | TPID | Standard |
|---|---|---|
| `Customer` | 0x8100 | IEEE 802.1Q C-tag |
| `Service` | 0x88A8 | IEEE 802.1ad S-tag |

## VlanTag

`Copy`, `Eq`, `Hash`. Wire form: TPID (2 octets) followed by TCI (2 octets), big-endian.

| Field | Bits of TCI | Range | Rule |
|---|---|---|---|
| `kind` | — | `TagKind` | — |
| `pcp` | 15–13 | 0–7 | `new` refuses > 7 |
| `dei` | 12 | bool | — |
| `vid` | 11–0 | 0–4095 | `new` refuses > 4095; 0 and 4095 accepted |

`tci()` = `pcp << 13 | dei << 12 | vid`. `from_tci` accepts any `u16`.

## Frame<'a>

`Copy`. Borrows the slice it was taken from. If built from a `Packet`, it borrows the packet's
lifetime and so ends at the next receive.

| Item | Value |
|---|---|
| `destination()` | octets 0–5 |
| `source()` | octets 6–11 |
| `vlan_tags()` | `&[VlanTag]` of length 0, 1 or 2, in wire order (outer first) |
| `ethertype()` | the 16 bits after the tags (a length if < 0x0600) |
| `header_len()` | 14 + 4 × tags |
| `payload()` | `&data[header_len..]`: padding included; captured part only when truncated |
| `as_bytes()` | the whole slice |

**Validity**: `len >= 14`, and for each tag announced (TPID at the EtherType position, at most
two) `len >= 14 + 4 × tags`. Otherwise there is no `Frame`.

## FrameBuilder

`Copy`. Built with `new(destination, source, ethertype)`, plus `vlan(tag)` or
`vlans(outer, inner)`.

| Operation | Result |
|---|---|
| `header_len()` | 14 + 4 × tags |
| `frame_len(payload_len)` | `max(header_len + payload_len, 60)` |
| `write(&mut Vec<u8>, payload)` | the `Vec` holds exactly the frame, zero-padded |
| `write_into(&mut [u8], payload)` | `Ok(len)` with `buf[..len]` the frame, or `Err(InvalidInput)` if `buf.len() < len` |

## Relationships

`Packet::frame() → Option<Frame>` · `Frame::reply(from) → Option<FrameBuilder>` ·
`FrameBuilder::write*` → bytes for `Socket::send`/`send_batch`/`send_at` · `Frame::new(built)`
round-trips.
