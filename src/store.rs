use super::stringpool::StringPool;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::hash::BuildHasherDefault;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::ops::RangeBounds;
use twox_hash::XxHash64;

#[derive(Debug, Clone)]
/// ASN is IP routing data identified by its whatever number
pub struct ASNEntry {
    asn: u32,
    country: [u8; 2],
    description: String,
}

impl ASNEntry {
    pub fn country(&self) -> &str {
        if self.country[0] != 0 {
            std::str::from_utf8(&self.country).unwrap_or("--")
        } else {
            "--"
        }
    }
}

#[cfg(feature = "serde")]
mod serde {
    use super::ASNEntry;
    use serde::{ser::SerializeStruct, Serialize};
    impl Serialize for ASNEntry {
        fn serialize<S>(&self, sz: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut state = sz.serialize_struct("ASNEntry", 3)?;
            state.serialize_field("asn", &self.asn)?;
            state.serialize_field("country", self.country())?;
            state.serialize_field("description", &self.description)?;
            state.end()
        }
    }
}

/// Range storage set
pub struct IPRangeSet<T: Ord + Send + Sync>(BTreeSet<IPRangeEntry<T>>);

/// Range storage entry
pub struct IPRangeEntry<T: PartialEq + Eq + PartialOrd + Ord + Sized + Send + Sync> {
    asn: u32,
    starts: T,
    ends: T,
}

impl<T: Ord + Eq + Send + Sync> Eq for IPRangeEntry<T> {}

impl<T: PartialEq + Ord + Send + Sync> PartialEq for IPRangeEntry<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.starts == other.starts
    }
}

impl<T: Ord + Send + Sync> PartialOrd for IPRangeEntry<T> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.starts.cmp(&other.starts))
    }
}

impl<T: Ord + Eq + Send + Sync> Ord for IPRangeEntry<T> {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.starts.cmp(&other.starts)
    }
}

impl<T: Ord + Send + Sync> RangeBounds<T> for IPRangeEntry<T> {
    #[inline]
    fn start_bound(&self) -> std::ops::Bound<&T> {
        std::ops::Bound::Included(&self.starts)
    }

    #[inline]
    fn end_bound(&self) -> std::ops::Bound<&T> {
        std::ops::Bound::Included(&self.ends)
    }
}

impl<T: Ord + Send + Sync + Default + Copy> IPRangeSet<T> {
    #[inline]
    pub fn insert(&mut self, starts: T, ends: T, asn: u32) {
        self.0.insert(IPRangeEntry { starts, ends, asn });
    }

    pub fn find<'a>(&'a self, needle: T) -> Option<&'a IPRangeEntry<T>> {
        let s = IPRangeEntry {
            starts: needle,
            ends: T::default(),
            asn: 0,
        };
        match self.0.range(..=s).last() {
            Some(o) => {
                if o.ends >= needle {
                    Some(o)
                } else {
                    None
                }
            }
            None => None,
        }
    }
}

/// IPv4+IPv6 Query system
pub struct IPDatabase {
    ipv4: IPRangeSet<u32>,
    ipv6: IPRangeSet<u128>,
    asn_map: HashMap<u32, ASNEntry, BuildHasherDefault<XxHash64>>,
}

const HEADER_SIZE: usize = 1024;
const SIGNATURE: &[u8; 16] = b"_IPRANGECACHE_DB";
const VERSION: u16 = 0x2;

impl IPDatabase {
    pub fn new() -> Self {
        Self {
            ipv4: IPRangeSet(BTreeSet::new()),
            ipv6: IPRangeSet(BTreeSet::new()),
            asn_map: HashMap::<_, _, BuildHasherDefault<XxHash64>>::default(),
        }
    }

    pub fn load_from_tsv_file(&mut self, path: &str) -> io::Result<()> {
        let file = std::fs::File::create(path)?;
        let mut file = std::io::BufReader::new(file);
        Self::load_from_tsv(self, &mut file)
    }

    pub fn load_from_tsv<F>(&mut self, path: &mut F) -> io::Result<()>
    where
        F: Read,
    {
        let mut contents = String::new();
        path.read_to_string(&mut contents)?;
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
                    self.ipv4.insert(u32::from(start), u32::from(end), asn);
                }
                (IpAddr::V6(start), IpAddr::V6(end)) => {
                    self.ipv6.insert(u128::from(start), u128::from(end), asn);
                }
                _ => continue,
            }
        }

        Ok(())
    }

    pub fn query<'a>(&'a self, ip: &str) -> Option<&'a ASNEntry> {
        if let Ok(parsed_ip) = ip.parse() {
            match parsed_ip {
                IpAddr::V4(ipv4) => self
                    .ipv4
                    .find(u32::from(ipv4))
                    .and_then(|i| self.asn_map.get(&i.asn)),
                IpAddr::V6(ipv6) => self
                    .ipv6
                    .find(u128::from(ipv6))
                    .and_then(|i| self.asn_map.get(&i.asn)),
            }
        } else {
            None
        }
    }

    pub fn save<F>(&self, file: &mut F) -> io::Result<()>
    where
        F: Write + Seek,
    {
        file.write_all(SIGNATURE)?;
        file.write_u16::<BigEndian>(VERSION)?;
        file.write_u64::<BigEndian>(0)?;
        file.write_u32::<BigEndian>(0)?;

        let asn_count = self.asn_map.len() as u32;
        let ipv4_count = self.ipv4.0.len() as u32;
        let ipv6_count = self.ipv6.0.len() as u32;

        file.write_u32::<BigEndian>(asn_count)?;
        file.write_u32::<BigEndian>(ipv4_count)?;
        file.write_u32::<BigEndian>(ipv6_count)?;

        const PADDING_SIZE: usize = HEADER_SIZE - (16 + 2 + 4 * 6);
        file.write(&[0u8; PADDING_SIZE])?;
        // file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

        // TODO: bring back hashcheck
        // let mut hasher = XxHash32::with_seed(727);
        let mut strpool = StringPool::new();

        for (asn, entry) in &self.asn_map {
            // let reg_asn = &asn.to_le_bytes();
            let reg_rgn = &entry.country;
            let reg_pds = &strpool.pack(&entry.description);

            // hasher.write(reg_asn);
            // hasher.write(reg_rgn);
            // hasher.write(reg_pds);

            file.write_u32::<BigEndian>(*asn)?;
            file.write(reg_rgn)?;
            file.write(reg_pds)?;
        }

        for i in self.ipv4.0.iter() {
            file.write_u32::<BigEndian>(i.starts)?;
            file.write_u32::<BigEndian>(i.ends)?;
            file.write_u32::<BigEndian>(i.asn)?;
        }

        for i in self.ipv6.0.iter() {
            file.write_u128::<BigEndian>(i.starts)?;
            file.write_u128::<BigEndian>(i.ends)?;
            file.write_u32::<BigEndian>(i.asn)?;
        }

        let strpl = file.stream_position()?;
        let reg_strpl = strpool.save().as_bytes();

        // hasher.write(reg_strpl);
        file.write_all(reg_strpl)?;

        file.seek(SeekFrom::Start(16 + 2))?;
        file.write_u32::<BigEndian>(strpl as u32)?;
        file.write_u32::<BigEndian>(reg_strpl.len() as u32)?;

        // let final_hash = hasher.finish_32();
        // file.write_u16::<BigEndian>(final_hash as u16)?;

        Ok(())
    }

    pub fn save_to_file(&self, path: &str) -> io::Result<()> {
        let file = File::create(path)?;
        let mut file = BufWriter::new(file);
        Self::save(&self, &mut file)
    }

    pub fn load<F>(file: &mut F) -> io::Result<Self>
    where
        F: Read + Write + Seek,
    {
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
            let end_ip = file.read_u32::<BigEndian>()?;
            let asn = file.read_u32::<BigEndian>()?;
            db.ipv4.insert(start_ip, end_ip, asn);
        }

        for _ in 0..ipv6_count {
            let start_ip = file.read_u128::<BigEndian>()?;
            let end_ip = file.read_u128::<BigEndian>()?;
            let asn = file.read_u32::<BigEndian>()?;
            db.ipv6.insert(start_ip, end_ip, asn);
        }

        Ok(db)
    }

    pub fn load_from_file(path: &str) -> io::Result<IPDatabase> {
        // let file = File::open(path)?;
        // let mut file = std::io::BufReader::new(file);
        let file = std::fs::read(path)?;
        let mut file = std::io::Cursor::new(file);
        Ok(Self::load(&mut file)?)
    }
}
