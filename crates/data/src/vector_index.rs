use crate::error::DataError;
use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};

/// Implements a two-stage vector database using binary quantization for coarse filtering and Int8 RaBitQ for exact rescoring.
pub struct MatryoshkaVectorStore {
    /// db
    pub db: Arc<Mutex<Connection>>,
}

impl MatryoshkaVectorStore {
    /// Initializes a new MatryoshkaVectorStore wrapping the provided database connection.
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        Self { db }
    }

    /// Normalizes, quantizes (1-bit and Int8), and persists a dense embedding vector into the store.
    pub fn insert_vector(&self, id: &str, vector: &[f32]) -> Result<(), DataError> {
        let conn = self.db.lock().unwrap();

        let mut packed_sign = [0u64; 8];
        for i in 0..512.min(vector.len()) {
            if vector[i] >= 0.0 {
                let u64_idx = i / 64;
                let bit_idx = i % 64;
                packed_sign[u64_idx] |= 1 << bit_idx;
            }
        }

        let mut max_abs = 0.0_f32;
        for &v in vector {
            let abs_v = v.abs();
            if abs_v > max_abs {
                max_abs = abs_v;
            }
        }

        let mut i8_vec = Vec::with_capacity(vector.len());
        let scale_factor = if max_abs > 0.0 { max_abs / 127.0 } else { 1.0 };
        for &v in vector {
            let q = (v / scale_factor).round() as i8;
            i8_vec.push(q);
        }

        let packed_sign_bytes: Vec<u8> =
            packed_sign.iter().flat_map(|&x| x.to_le_bytes()).collect();
        let i8_vec_bytes: Vec<u8> = i8_vec.iter().map(|&x| x as u8).collect(); // reinterpreting i8 to u8 for storage

        conn.execute(
            "CREATE TABLE IF NOT EXISTS vector_index (
                id TEXT PRIMARY KEY,
                packed_sign_blob BLOB,
                i8_vec_blob BLOB,
                scale_factor REAL
            )",
            [],
        )?;

        conn.execute(
            "INSERT INTO vector_index (id, packed_sign_blob, i8_vec_blob, scale_factor) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET packed_sign_blob=excluded.packed_sign_blob, i8_vec_blob=excluded.i8_vec_blob, scale_factor=excluded.scale_factor",
            params![id, packed_sign_bytes, i8_vec_bytes, scale_factor]
        )?;

        Ok(())
    }

    /// Executes a two-stage asymmetric search, scanning binary signs via Hamming distance before rescoring top candidates using RaBitQ cosine similarity.
    pub fn search(
        &self,
        query: &[f32],
        top_k: usize,
        threshold: f32,
    ) -> Result<Vec<(String, f32)>, DataError> {
        let conn = self.db.lock().unwrap();

        let mut q_packed_sign = [0u64; 8];
        for i in 0..512.min(query.len()) {
            if query[i] >= 0.0 {
                let u64_idx = i / 64;
                let bit_idx = i % 64;
                q_packed_sign[u64_idx] |= 1 << bit_idx;
            }
        }

        // Retrieve candidates and stage 1 filtering
        let mut stmt = conn
            .prepare("SELECT id, packed_sign_blob, i8_vec_blob, scale_factor FROM vector_index")?;
        let mut rows = stmt.query([])?;

        let mut candidates = Vec::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let packed_sign_bytes: Vec<u8> = row.get(1)?;
            let i8_vec_bytes: Vec<u8> = row.get(2)?;
            let scale_factor: f32 = row.get(3)?;

            let mut candidate_packed = [0u64; 8];
            for i in 0..8 {
                let start = i * 8;
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&packed_sign_bytes[start..start + 8]);
                candidate_packed[i] = u64::from_le_bytes(buf);
            }

            let mut hamming_dist = 0;
            for i in 0..8 {
                hamming_dist += (q_packed_sign[i] ^ candidate_packed[i]).count_ones();
            }

            candidates.push((id, hamming_dist, i8_vec_bytes, scale_factor));
        }

        // Sort by hamming distance (ascending) and take top K1 = 4096
        candidates.sort_by_key(|c| c.1);
        let k1 = 4096.min(candidates.len());
        candidates.truncate(k1);

        let mut results = Vec::new();
        for (id, _, i8_vec_bytes, scale_factor) in candidates {
            // Stage 2 Rescoring
            let mut dot_product = 0.0;
            let mut q_norm_sq = 0.0;
            let mut v_norm_sq = 0.0;

            for (i, &q) in query.iter().enumerate() {
                if i < i8_vec_bytes.len() {
                    let v_i8 = i8_vec_bytes[i] as i8;
                    let v_f32 = (v_i8 as f32) * scale_factor;

                    dot_product += q * v_f32;
                    q_norm_sq += q * q;
                    v_norm_sq += v_f32 * v_f32;
                }
            }

            let similarity = if q_norm_sq > 0.0 && v_norm_sq > 0.0 {
                dot_product / (q_norm_sq.sqrt() * v_norm_sq.sqrt())
            } else {
                0.0
            };

            if similarity >= threshold {
                results.push((id, similarity));
            }
        }

        // Sort by similarity descending
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(top_k);

        Ok(results)
    }
}
