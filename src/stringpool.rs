use std::{collections::HashMap, hash::BuildHasherDefault};
use twox_hash::XxHash64;

pub struct StringPool {
    pool: String,
    cache: HashMap<String, (u32, u32), BuildHasherDefault<XxHash64>>,
}

impl StringPool {
    #[inline]
    pub fn new() -> Self {
        Self {
            pool: String::new(),
            cache: HashMap::<_, _, BuildHasherDefault<XxHash64>>::default(),
        }
    }

    #[inline]
    pub fn load(pool: String) -> Self {
        Self {
            pool,
            cache: HashMap::<_, _, BuildHasherDefault<XxHash64>>::default(),
        }
    }

    #[inline]
    pub fn save<'a>(&'a self) -> &'a String {
        &self.pool
    }

    pub fn pack(&mut self, slice: &str) -> [u8; 8] {
        self.cache.get(slice).map(|&(start_index, length)| {
            let mut output = [0u8; 8];
            output[..4].copy_from_slice(&start_index.to_le_bytes());
            output[4..].copy_from_slice(&length.to_le_bytes());
            return output;
        });

        let start_index = self.pool.len() as u32;
        self.pool.push_str(slice);
        let length = slice.len() as u32;
        self.cache.insert(slice.to_string(), (start_index, length)); // Cache the position and length

        let mut output = [0u8; 8];
        output[..4].copy_from_slice(&start_index.to_le_bytes());
        output[4..].copy_from_slice(&length.to_le_bytes());
        output
    }

    pub fn unpack<'a>(&'a self, data: &[u8; 8]) -> &'a str {
        let start_index = u32::from_le_bytes(
            data[..4]
                .try_into()
                .expect("Failed to convert start index from bytes."),
        ) as usize;
        let length = u32::from_le_bytes(
            data[4..]
                .try_into()
                .expect("Failed to convert length from bytes."),
        ) as usize;

        if start_index + length > self.pool.len() {
            eprintln!("Warning: Unpack indices {start_index} out of bounds.");
            return "";
        }

        &self.pool[start_index..start_index + length]
    }
}
