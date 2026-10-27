use aes::Aes256;
use aes::cipher::{
    Block, BlockCipherDecrypt, BlockModeDecrypt, KeyInit as CipherKeyInit, KeyIvInit,
    block_padding::Pkcs7,
};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::Aead};
use chrono::{DateTime, Utc};
use clap::Parser;
use lopdf::{Document, Object, ObjectId, ObjectStream, Reader, xref::XrefEntry};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const DAY: u64 = 86_400;
const CHUNK_SIZE: u64 = 4_096;
const NOT_FOUND: u64 = u64::MAX;

type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[derive(Parser)]
#[command(about = "Decrypt Foxit PDFs with timestamp-derived AES-256 keys")]
struct Args {
    input: PathBuf,
    output: PathBuf,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    AesV3,
    AesV4,
}

#[derive(Clone, Copy)]
struct EncryptionInfo {
    mode: Mode,
    encryption_object: ObjectId,
    perms: [u8; 16],
    permissions: [u8; 4],
    metadata: u8,
    encrypt_metadata: bool,
    encrypt_streams: bool,
    encrypt_strings: bool,
}

impl EncryptionInfo {
    fn from_document(document: &Document) -> Result<Self> {
        let encryption_object = document
            .trailer
            .get(b"Encrypt")?
            .as_reference()
            .map_err(|_| invalid("trailer /Encrypt is not an indirect reference"))?;
        let dictionary = document.get_dictionary(encryption_object)?;
        let revision = dictionary.get(b"R")?.as_i64()?;
        let crypt_filter = dictionary.get(b"CF")?.as_dict()?.get(b"StdCF")?.as_dict()?;
        let method = crypt_filter.get(b"CFM")?.as_name()?;
        let mode = match (revision, method) {
            (6, b"AESV3") => Mode::AesV3,
            (7, b"AESV4") => Mode::AesV4,
            _ => {
                return Err(invalid(format!(
                    "unsupported encryption revision {revision} and method /{}",
                    String::from_utf8_lossy(method)
                ))
                .into());
            }
        };
        let perms = dictionary
            .get(b"Perms")?
            .as_str()?
            .try_into()
            .map_err(|_| invalid("unsupported /Perms length"))?;
        let permissions = (dictionary.get(b"P")?.as_i64()? as i32).to_le_bytes();
        let encrypt_metadata = dictionary
            .get(b"EncryptMetadata")
            .ok()
            .map(Object::as_bool)
            .transpose()?
            .unwrap_or(true);
        let encrypt_streams = dictionary
            .get(b"StmF")
            .ok()
            .map(Object::as_name)
            .transpose()?
            .is_none_or(|name| name != b"Identity");
        let encrypt_strings = dictionary
            .get(b"StrF")
            .ok()
            .map(Object::as_name)
            .transpose()?
            .is_none_or(|name| name != b"Identity");

        Ok(Self {
            mode,
            encryption_object,
            perms,
            permissions,
            metadata: if encrypt_metadata { b'T' } else { b'F' },
            encrypt_metadata,
            encrypt_streams,
            encrypt_strings,
        })
    }

    fn try_timestamp(&self, timestamp: u32) -> Option<[u8; 32]> {
        let mut material = [0u8; 41];
        material[..4].copy_from_slice(&timestamp.to_le_bytes());
        material[36..].copy_from_slice(b"there");
        let key: [u8; 32] = Sha256::digest(material).into();

        let cipher = Aes256::new(&key.into());
        let mut plain = Block::<Aes256>::from(self.perms);
        cipher.decrypt_block(&mut plain);
        (plain[..4] == self.permissions
            && plain[4..8] == [0xff; 4]
            && plain[8] == self.metadata
            && plain[9..12] == *b"adb")
            .then_some(key)
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn timestamp_text(timestamp: u32) -> String {
    DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| timestamp.to_string())
}

fn search_key(info: EncryptionInfo) -> Result<(u32, [u8; 32], u64, f64)> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let start = (now + DAY).min(u32::MAX as u64);
    let threads = rayon::current_num_threads();
    eprintln!(
        "searching downward from {} ({}) with {} threads",
        start,
        timestamp_text(start as u32),
        threads
    );

    let next_offset = AtomicU64::new(0);
    let found = AtomicU64::new(NOT_FOUND);
    let tested = AtomicU64::new(0);
    let candidate_count = start + 1;
    let began = Instant::now();

    rayon::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|_| {
                let mut local_tested = 0;
                while found.load(Ordering::Relaxed) == NOT_FOUND {
                    let offset = next_offset.fetch_add(CHUNK_SIZE, Ordering::Relaxed);
                    if offset >= candidate_count {
                        break;
                    }
                    let end = (offset + CHUNK_SIZE).min(candidate_count);
                    for offset in offset..end {
                        if found.load(Ordering::Relaxed) != NOT_FOUND {
                            break;
                        }
                        let timestamp = (start - offset) as u32;
                        local_tested += 1;
                        if info.try_timestamp(timestamp).is_some() {
                            let _ = found.compare_exchange(
                                NOT_FOUND,
                                timestamp as u64,
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                            );
                            break;
                        }
                    }
                }
                tested.fetch_add(local_tested, Ordering::Relaxed);
            });
        }
    });

    let timestamp = found.load(Ordering::Relaxed);
    if timestamp == NOT_FOUND {
        return Err(invalid("no key found between the starting timestamp and zero").into());
    }
    let timestamp = timestamp as u32;
    let key = info
        .try_timestamp(timestamp)
        .ok_or_else(|| invalid("recovered timestamp failed key verification"))?;
    Ok((
        timestamp,
        key,
        tested.load(Ordering::Relaxed),
        began.elapsed().as_secs_f64(),
    ))
}

fn decrypt_bytes(mode: Mode, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    match mode {
        Mode::AesV3 => {
            if ciphertext.len() < 32 || !ciphertext.len().is_multiple_of(16) {
                return Err(invalid("invalid AESV3 ciphertext length").into());
            }
            let (iv, encrypted) = ciphertext.split_at(16);
            let iv: &[u8; 16] = iv
                .try_into()
                .map_err(|_| invalid("invalid AESV3 IV length"))?;
            let mut buffer = encrypted.to_vec();
            let plaintext = Aes256CbcDec::new(key.into(), iv.into())
                .decrypt_padded::<Pkcs7>(&mut buffer)
                .map_err(|_| invalid("invalid AESV3 padding"))?;
            Ok(plaintext.to_vec())
        }
        Mode::AesV4 => {
            if ciphertext.len() < 28 {
                return Err(invalid("invalid AESV4 ciphertext length").into());
            }
            let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new(&Key::<Aes256Gcm>::from(*key));
            let nonce: [u8; 12] = ciphertext[..12]
                .try_into()
                .map_err(|_| invalid("invalid AESV4 nonce length"))?;
            cipher
                .decrypt(&Nonce::from(nonce), &ciphertext[12..])
                .map_err(|_| invalid("AESV4 authentication failed").into())
        }
    }
}

fn stream_uses_identity(stream: &lopdf::Stream) -> bool {
    let Ok(filters) = stream.filters() else {
        return false;
    };
    if !filters.contains(&&b"Crypt"[..]) {
        return false;
    }
    stream
        .dict
        .get(b"DecodeParms")
        .ok()
        .and_then(|value| value.as_dict().ok())
        .and_then(|dictionary| dictionary.get(b"Name").ok())
        .and_then(|value| value.as_name().ok())
        .is_none_or(|name| name == b"Identity")
}

fn decrypt_object(object: &mut Object, info: EncryptionInfo, key: &[u8; 32]) -> Result<()> {
    if object
        .as_stream()
        .is_ok_and(|stream| stream.dict.has_type(b"XRef"))
    {
        return Ok(());
    }
    if object.type_name().ok() == Some(b"Metadata") && !info.encrypt_metadata {
        return Ok(());
    }

    match object {
        Object::Array(values) => {
            for value in values {
                decrypt_object(value, info, key)?;
            }
        }
        Object::Dictionary(dictionary) => {
            for (_, value) in dictionary.iter_mut() {
                decrypt_object(value, info, key)?;
            }
        }
        Object::String(content, _) if info.encrypt_strings => {
            *content = decrypt_bytes(info.mode, key, content)?;
        }
        Object::Stream(stream) if info.encrypt_streams && !stream_uses_identity(stream) => {
            stream.set_content(decrypt_bytes(info.mode, key, &stream.content)?);
        }
        _ => {}
    }
    Ok(())
}

fn decrypt_document(document: &mut Document, info: EncryptionInfo, key: &[u8; 32]) -> Result<()> {
    for (&id, object) in &mut document.objects {
        if id != info.encryption_object {
            decrypt_object(object, info, key)?;
        }
    }

    let mut compressed_objects = Vec::new();
    for object in document.objects.values_mut() {
        let Ok(stream) = object.as_stream_mut() else {
            continue;
        };
        if stream.dict.has_type(b"ObjStm") {
            compressed_objects.extend(ObjectStream::new(stream)?.objects);
        }
    }
    for (id, object) in compressed_objects {
        document.objects.entry(id).or_insert(object);
    }

    document.trailer.remove(b"Encrypt");
    document.objects.remove(&info.encryption_object);
    Ok(())
}

fn load_encrypted_pdf(path: &PathBuf) -> Result<Document> {
    let bytes = fs::read(path)?;
    let document = Document::load_mem(&bytes)?;
    let entries: Vec<_> = document
        .reference_table
        .entries
        .iter()
        .map(|(&number, entry)| (number, entry.clone()))
        .collect();
    let mut reader = Reader {
        buffer: &bytes,
        document,
        encryption_state: None,
        raw_objects: BTreeMap::new(),
        password: None,
        strict: false,
        max_decompressed_size: None,
    };

    for (number, entry) in entries {
        let XrefEntry::Normal { generation, .. } = entry else {
            continue;
        };
        let id = (number, generation);
        let object = reader.get_object(id, &mut HashSet::new())?;
        reader.document.objects.insert(id, object);
    }
    Ok(reader.document)
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.input == args.output {
        return Err(invalid("input and output paths must differ").into());
    }

    let mut document = load_encrypted_pdf(&args.input)?;
    let info = EncryptionInfo::from_document(&document)?;
    let (timestamp, key, tested, elapsed) = search_key(info)?;
    eprintln!(
        "found timestamp {} ({}) after testing {} candidates in {:.3}s ({:.3} million/s)",
        timestamp,
        timestamp_text(timestamp),
        tested,
        elapsed,
        tested as f64 / elapsed / 1_000_000.0
    );

    decrypt_document(&mut document, info, &key)?;
    document.save(&args.output)?;
    eprintln!("wrote {}", args.output.display());
    Ok(())
}
