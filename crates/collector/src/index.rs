//! Index tables as Parquet (spec §8), one file per table per window.
//!
//! Rows arrive as the JSON the local tables hold, and their columns come
//! from the schemas in [`bundle::index`].

use std::sync::Arc;

pub use bundle::index::*;
use parquet::basic::{Compression, LogicalType, Repetition, Type as Physical, ZstdLevel};
use parquet::data_type::{BoolType, ByteArray, ByteArrayType, DoubleType, Int64Type};
use parquet::errors::Result;
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::types::Type;
use serde_json::Value;

use Kind::{Bool, Float, Int, Json, Str};

fn get<'a>(row: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(row, |v, k| v.get(k))
        .filter(|v| !v.is_null())
}

/// The Parquet bytes of one table's rows.
pub fn parquet(table: &str, rows: &[Value]) -> Result<Vec<u8>> {
    let columns = schema(table);
    let fields = columns
        .iter()
        .map(|&(path, kind)| {
            let name = path.replace('.', "_");
            let (physical, logical) = match kind {
                Int => (Physical::INT64, None),
                Float => (Physical::DOUBLE, None),
                Bool => (Physical::BOOLEAN, None),
                Str => (Physical::BYTE_ARRAY, Some(LogicalType::String)),
                Json => (Physical::BYTE_ARRAY, Some(LogicalType::Json)),
            };
            Type::primitive_type_builder(&name, physical)
                .with_repetition(Repetition::OPTIONAL)
                .with_logical_type(logical)
                .build()
                .map(Arc::new)
        })
        .collect::<Result<Vec<_>>>()?;
    let schema = Type::group_type_builder(table).with_fields(fields).build()?;
    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::default()))
        .set_created_by("tokenspectra-collector".into())
        .build();
    let mut w = SerializedFileWriter::new(Vec::new(), Arc::new(schema), Arc::new(props))?;
    let mut rg = w.next_row_group()?;
    let mut i = 0;
    while let Some(mut col) = rg.next_column()? {
        let (path, kind) = columns[i];
        i += 1;
        let values: Vec<Option<&Value>> = rows.iter().map(|r| get(r, path)).collect();
        let defs: Vec<i16> = values.iter().map(|v| i16::from(v.is_some())).collect();
        let present = values.iter().flatten();
        match kind {
            Int => {
                let v: Vec<i64> = present
                    .map(|v| {
                        v.as_i64()
                            .or_else(|| v.as_u64().map(|u| u as i64))
                            .unwrap_or_default()
                    })
                    .collect();
                col.typed::<Int64Type>().write_batch(&v, Some(&defs), None)?;
            }
            Float => {
                let v: Vec<f64> = present.map(|v| v.as_f64().unwrap_or_default()).collect();
                col.typed::<DoubleType>().write_batch(&v, Some(&defs), None)?;
            }
            Bool => {
                let v: Vec<bool> = present.map(|v| v.as_bool().unwrap_or_default()).collect();
                col.typed::<BoolType>().write_batch(&v, Some(&defs), None)?;
            }
            Str | Json => {
                let v: Vec<ByteArray> = present
                    .map(|v| match (kind, v) {
                        (Str, Value::String(s)) => ByteArray::from(s.as_str()),
                        _ => ByteArray::from(v.to_string().into_bytes()),
                    })
                    .collect();
                col.typed::<ByteArrayType>().write_batch(&v, Some(&defs), None)?;
            }
        }
        col.close()?;
    }
    rg.close()?;
    w.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use serde_json::json;

    #[test]
    fn rows_round_trip_through_parquet() {
        let rows = vec![
            json!({"link": "lo", "window_start_ns": 10, "index": 0, "ts_ns": 11, "cap_len": 60,
                   "orig_len": 60, "hash": "f1e20", "flow": null, "dir": null, "tcp_flags": null,
                   "stream_off": -3, "payload_len": null, "note": "not_ip"}),
            json!({"link": "lo", "window_start_ns": 10, "index": 1, "ts_ns": 12, "cap_len": 54,
                   "orig_len": 54, "hash": "f1e21", "flow": "x", "dir": "orig", "tcp_flags": "S",
                   "stream_off": 0, "payload_len": 0, "note": null}),
        ];
        assert!(rows.iter().all(|r| uncovered("packets", r).is_empty()));
        let bytes = parquet("packets", &rows).unwrap();
        let reader = SerializedFileReader::new(bytes::Bytes::from(bytes)).unwrap();
        assert_eq!(reader.metadata().file_metadata().num_rows(), 2);
        let got: Vec<String> = reader
            .get_row_iter(None)
            .unwrap()
            .map(|r| r.unwrap().to_string())
            .collect();
        assert!(got[0].contains("stream_off: -3"), "{}", got[0]);
        assert!(got[0].contains("flow: null"), "{}", got[0]);
        assert!(got[1].contains("tcp_flags: \"S\""), "{}", got[1]);
    }

    #[test]
    fn floats_and_family_columns_round_trip() {
        let rows = vec![
            json!({"window_start_ns": 10, "flow": "f", "link": "tap0",
                   "dns": {"messages": 2, "query_rate": 1.5, "qname_entropy_max": 4.619, "txt_max": null}}),
            json!({"window_start_ns": 10, "flow": "g", "link": "tap0", "dns": null}),
        ];
        assert!(uncovered("features", &rows[0]).is_empty());
        let bytes = parquet("features", &rows).unwrap();
        let reader = SerializedFileReader::new(bytes::Bytes::from(bytes)).unwrap();
        let got: Vec<String> = reader
            .get_row_iter(None)
            .unwrap()
            .map(|r| r.unwrap().to_string())
            .collect();
        assert!(got[0].contains("dns_query_rate: 1.5"), "{}", got[0]);
        assert!(got[0].contains("dns_qname_entropy_max: 4.619"), "{}", got[0]);
        assert!(got[0].contains("dns_txt_max: null"), "{}", got[0]);
        assert!(got[1].contains("dns_messages: null"), "{}", got[1]);
    }
}
