//! Minimal DAG-CBOR encoder for PLC operations.
//!
//! PLC ops only contain maps, arrays, strings and null, so this covers exactly the
//! JSON shapes we need and rejects everything else. Map keys are sorted the DAG-CBOR
//! way: shorter keys first, then bytewise.

use anyhow::{Result, bail};
use serde_json::Value;

pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    write_value(&mut out, value)?;
    Ok(out)
}

fn write_value(out: &mut Vec<u8>, value: &Value) -> Result<()> {
    match value {
        Value::Null => out.push(0xf6),
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Number(n) => match (n.as_u64(), n.as_i64()) {
            (Some(u), _) => write_head(out, 0, u),
            (None, Some(i)) => write_head(out, 1, (-1 - i) as u64),
            _ => bail!("floats are not allowed in PLC operations"),
        },
        Value::String(s) => write_str(out, s),
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                write_value(out, item)?;
            }
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.as_bytes().cmp(b.as_bytes())));
            write_head(out, 5, keys.len() as u64);
            for key in keys {
                write_str(out, key);
                write_value(out, &map[key])?;
            }
        }
    }
    Ok(())
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    write_head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}
