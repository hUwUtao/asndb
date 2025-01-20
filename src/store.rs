use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use twox_hash::{XxHash32, XxHash64};

use super::stringpool::StringPool;

#[derive(Debug, Clone)]
/// ASN is IP routing data identified by its whatever number
pub struct ASNEntry {
    asn: u32,
    country: [u8; 2],
    description: String,
}

#[cfg(feature = "serde")]
mod serde {
    use super::ASNEntry;
    use serde::Serialize;
    impl Serialize for ASNEntry {
        fn serialize<S>(&self, sz: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeStruct;
            let mut state = sz.serialize_struct("ASNEntry", 3)?;
            state.serialize_field("asn", &self.asn)?;
            let country = std::str::from_utf8(&self.country).map_err(serde::ser::Error::custom)?;
            state.serialize_field("country", country)?;
            state.serialize_field("description", &self.description)?;
            state.end()
        }
    }
}

#[derive(Debug)]
/// ### Main implementation
/// Quickly range start and end by btree (since the data is optimized)
pub struct IPDatabase {
    ipv4_starts: BTreeMap<u32, u32>,
    ipv4_ends: BTreeMap<u32, u32>,
    ipv6_starts: BTreeMap<u128, u32>,
    ipv6_ends: BTreeMap<u128, u32>,
    asn_map: HashMap<u32, ASNEntry, BuildHasherDefault<XxHash64>>,
}

const HEADER_SIZE: usize = 1024;
const SIGNATURE: &[u8; 16] = b"_IPRANGECACHE_DB";
const VERSION: u16 = 0x1;

impl IPDatabase {
    pub fn new() -> Self {
        Self {
            ipv4_starts: BTreeMap::new(),
            ipv4_ends: BTreeMap::new(),
            ipv6_starts: BTreeMap::new(),
            ipv6_ends: BTreeMap::new(),
            asn_map: HashMap::<_, _, BuildHasherDefault<XxHash64>>::default(),
        }
    }

    pub fn load_from_tsv(&mut self, path: &str) -> io::Result<()> {
        let contents = std::fs::read_to_string(path)?;

        for line in contents.split('\n') {
            let mut fields = line.split('\t').take(5);

            let (range_start, range_end, asn) = match (fields.next(), fields.next(), fields.next())
            {
                (Some(start), Some(end), Some(asn_str)) => {
                    match (start.parse(), end.parse(), asn_str.parse()) {
                        (Ok(s), Ok(e), Ok(a)) => (s, e, a),
                        _ => continue,
                    }
                }
                _ => continue,
            };

            let country_code = match fields.next() {
                Some(cc) => cc.as_bytes(),
                None => continue,
            };

            let description = match fields.next() {
                Some(desc) => desc.to_string(),
                None => continue,
            };

            let mut country = [0; 2];
            if country_code.len() == 2 {
                country[..2].copy_from_slice(&country_code[..2]);
            }

            self.asn_map.insert(
                asn,
                ASNEntry {
                    asn,
                    country,
                    description,
                },
            );

            match (range_start, range_end) {
                (IpAddr::V4(start), IpAddr::V4(end)) => {
                    self.ipv4_starts.insert(u32::from(start), asn);
                    self.ipv4_ends.insert(u32::from(end), asn);
                }
                (IpAddr::V6(start), IpAddr::V6(end)) => {
                    self.ipv6_starts.insert(u128::from(start), asn);
                    self.ipv6_ends.insert(u128::from(end), asn);
                }
                _ => continue,
            }
        }

        Ok(())
    }

    pub fn query(&self, ip: &str) -> Option<ASNEntry> {
        if let Ok(parsed_ip) = ip.parse() {
            match parsed_ip {
                IpAddr::V4(ipv4) => {
                    let ip_num = u32::from(ipv4);
                    if let Some(asn) = self.ipv4_starts.range(..=ip_num).last().map(|(_, &v)| v) {
                        if self.ipv4_ends.range(ip_num..).next().map(|(_, &f)| f) == Some(asn) {
                            return self.asn_map.get(&asn).cloned();
                        }
                    }
                }
                IpAddr::V6(ipv6) => {
                    let ip_num = u128::from(ipv6);
                    if let Some(asn) = self.ipv6_starts.range(..=ip_num).last().map(|(_, &v)| v) {
                        if self.ipv6_ends.range(ip_num..).next().map(|(_, &f)| f) == Some(asn) {
                            return self.asn_map.get(&asn).cloned();
                        }
                    }
                }
            }
        }
        None
    }

    pub fn save_to_file(&self, path: &str) -> io::Result<()> {
        let file = File::create(path)?;
        let mut file = BufWriter::new(file);
        file.write_all(SIGNATURE)?;
        file.write_u16::<BigEndian>(VERSION)?;
        file.write_u64::<BigEndian>(0)?;
        file.write_u32::<BigEndian>(0)?;

        let asn_count = self.asn_map.len() as u32;
        let ipv4_count = self.ipv4_starts.len() as u32;
        let ipv6_count = self.ipv6_starts.len() as u32;

        file.write_u32::<BigEndian>(asn_count)?;
        file.write_u32::<BigEndian>(ipv4_count)?;
        file.write_u32::<BigEndian>(ipv6_count)?;

        const PADDING_SIZE: usize = HEADER_SIZE - (16 + 2 + 4 * 6);
        file.write(&[0u8; PADDING_SIZE])?;
        // file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

        let mut hasher = XxHash32::with_seed(727);
        let mut strpool = StringPool::new();

        for (asn, entry) in &self.asn_map {
            let reg_asn = &asn.to_le_bytes();
            let reg_rgn = &entry.country;
            let reg_pds = &strpool.pack(&entry.description);

            hasher.write(reg_asn);
            hasher.write(reg_rgn);
            hasher.write(reg_pds);

            file.write_u32::<BigEndian>(*asn)?;
            file.write(reg_rgn)?;
            file.write(reg_pds)?;
        }

        for (entry, asn) in self.ipv4_starts.iter().chain(&self.ipv4_ends) {
            file.write_u32::<BigEndian>(*entry)?;
            file.write_u32::<BigEndian>(*asn)?;
        }

        for (entry, asn) in self.ipv6_starts.iter().chain(&self.ipv6_ends) {
            file.write_u128::<BigEndian>(*entry)?;
            file.write_u32::<BigEndian>(*asn)?;
        }

        let strpl = file.stream_position()?;
        let reg_strpl = strpool.save().as_bytes();

        hasher.write(reg_strpl);
        file.write_all(reg_strpl)?;

        file.seek(SeekFrom::Start(16 + 2))?;
        file.write_u32::<BigEndian>(strpl as u32)?;
        file.write_u32::<BigEndian>(reg_strpl.len() as u32)?;

        let final_hash = hasher.finish_32();
        file.write_u16::<BigEndian>(final_hash as u16)?;

        Ok(())
    }

    pub fn load_from_file(path: &str) -> io::Result<Self> {
        let file = File::open(path)?;
        // let file = std::fs::read(path)?;
        // let file = Cursor::new(file);
        let mut file = BufReader::new(file);
        let mut header = [0; HEADER_SIZE];
        file.read_exact(&mut header)?;

        // Validate header
        if &header[..16] != SIGNATURE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid signature",
            ));
        }
        let version = BigEndian::read_u16(&header[16..18]);
        if version != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid version",
            ));
        }
        let asn_count = BigEndian::read_u32(&header[30..34]);
        let ipv4_count = BigEndian::read_u32(&header[34..38]);
        let ipv6_count = BigEndian::read_u32(&header[38..42]);

        // Load string pool
        let strpl_position = BigEndian::read_u32(&header[18..22]);
        let str_length = BigEndian::read_u32(&header[22..26]) as usize;
        file.seek(SeekFrom::Start(strpl_position as u64))?;
        let mut strpl_buf = String::with_capacity(str_length);
        file.read_to_string(&mut strpl_buf)?;
        let strpool = StringPool::load(strpl_buf);

        let mut db = IPDatabase::new();
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

        for _ in 0..asn_count {
            // let _hash = file.read_u32::<BigEndian>()?;
            let asn = file.read_u32::<BigEndian>()?;
            let mut country = [0; 2];
            file.read_exact(&mut country)?;
            let mut des = [0; 8];
            file.read_exact(&mut des)?;
            let description = strpool.unpack(&des).to_string();

            db.asn_map.insert(
                asn,
                ASNEntry {
                    asn,
                    country,
                    description,
                },
            );
        }

        for _ in 0..ipv4_count {
            let start_ip = file.read_u32::<BigEndian>()?;
            let asn = file.read_u32::<BigEndian>()?;
            db.ipv4_starts.insert(start_ip, asn);
        }

        for _ in 0..ipv4_count {
            let end_ip = file.read_u32::<BigEndian>()?;
            let asn = file.read_u32::<BigEndian>()?;
            db.ipv4_ends.insert(end_ip, asn);
        }

        for _ in 0..ipv6_count {
            let start_ip = file.read_u128::<BigEndian>()?;
            let asn = file.read_u32::<BigEndian>()?;
            db.ipv6_starts.insert(start_ip, asn);
        }

        for _ in 0..ipv6_count {
            let end_ip = file.read_u128::<BigEndian>()?;
            let asn = file.read_u32::<BigEndian>()?;
            db.ipv6_ends.insert(end_ip, asn);
        }

        Ok(db)
    }
}
