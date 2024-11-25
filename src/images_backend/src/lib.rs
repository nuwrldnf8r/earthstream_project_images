use ic_cdk_macros::{query, update};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use candid::CandidType;

// File identifier (SHA-256 hash)
type FileId = [u8; 32];
type ChunkId = u64;

const MAX_FILE_SIZE: usize = 200 * 1024; // 200KB
const CHUNK_SIZE: usize = 4 * 1024; // 4KB

#[derive(Serialize, Deserialize)]
struct Metadata {
    file_size: u32,
    mime_type: String,
    chunks: Vec<ChunkId>,
}

#[derive(Default)]
struct CanisterStorage {
    metadata: HashMap<FileId, Metadata>, // File metadata
    chunks: HashMap<ChunkId, Vec<u8>>,  // Chunk data
    next_chunk_id: ChunkId,             // Next available chunk ID
}

#[derive(CandidType, Serialize, Deserialize)]
enum DownloadResult {
    Ok {
        mime_type: String,
        file: Vec<u8>,
    },
    Err(String),
}

// Storage management
thread_local! {
    static STORAGE: RefCell<CanisterStorage> = RefCell::new(CanisterStorage::default());
}

/// Upload a file
#[update]
fn upload_file(file: Vec<u8>, mime_type: String) -> Result<FileId, String> {
    if file.len() > MAX_FILE_SIZE {
        return Err(format!(
            "File size exceeds the limit of {} KB",
            MAX_FILE_SIZE / 1024
        ));
    }

    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(&file);
    let file_id: FileId = hasher.finalize().into();

    STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();

        // Check if the file already exists
        if storage.metadata.contains_key(&file_id) {
            return Ok(file_id);
        }

        // Chunk the file and store chunks
        let mut chunks = Vec::new();
        for chunk in file.chunks(CHUNK_SIZE) {
            let chunk_id = storage.next_chunk_id;
            storage.chunks.insert(chunk_id, chunk.to_vec());
            storage.next_chunk_id += 1;
            chunks.push(chunk_id);
        }

        // Store metadata
        storage.metadata.insert(
            file_id,
            Metadata {
                file_size: file.len() as u32,
                mime_type,
                chunks,
            },
        );

        // Return the computed file ID
        Ok(file_id)
    })
}

/// Retrieve a file by its hexadecimal string ID
#[query]
fn get_file(file_id_hex: String) -> DownloadResult {
    let file_id: Result<FileId, String> = hex::decode(file_id_hex)
        .map_err(|_| "Invalid hex string for file ID".to_string())
        .and_then(|decoded| decoded.try_into().map_err(|_| "Invalid file ID length".to_string()));

    if let Err(err) = file_id {
        return DownloadResult::Err(err);
    }

    let file_id = file_id.unwrap();

    STORAGE.with(|storage| {
        let storage = storage.borrow();

        if let Some(metadata) = storage.metadata.get(&file_id) {
            // Reassemble the file from chunks
            let mut file = Vec::with_capacity(metadata.file_size as usize);
            for &chunk_id in &metadata.chunks {
                if let Some(chunk) = storage.chunks.get(&chunk_id) {
                    file.extend_from_slice(chunk);
                } else {
                    return DownloadResult::Err("Missing file chunk".to_string());
                }
            }

            DownloadResult::Ok {
                mime_type: metadata.mime_type.clone(),
                file,
            }
        } else {
            DownloadResult::Err("File not found".to_string())
        }
    })
}




/// Get the total number of uploaded images
#[query]
fn get_image_count() -> u64 {
    STORAGE.with(|storage| {
        let storage = storage.borrow();
        storage.metadata.len() as u64
    })
}
