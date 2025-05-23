use clap::Parser;
use ring::digest;
use ring::aead;
use ring::pbkdf2;
use std::fs::File;
use std::io::{self, Read, Write};
use rand::rngs::OsRng;
use rand::RngCore;
use hex::decode;
use secrecy::{SecretString, ExposeSecret};
use ring::rand::SecureRandom;
use walkdir::WalkDir; 
use std::path::{Path, PathBuf};

use std::time::{SystemTime, UNIX_EPOCH};
use image::{ImageReader, Rgba, GenericImageView}; 

// Константи
const KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE: u8 = 0x00;
const KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE: u8 = 0x01;
const KEY_MANAGEMENT_FLAG_ENCRYPTED_KEY_FILE: u8 = 0x02;

const PBKDF2_SALT_LEN: usize = 16;
const PBKDF2_ITERATIONS: u32 = 100_000;
const PBKDF2_BYTES: usize = 32; // Довжина ключа, отриманого з пароля (для AES-256)

// Константи для роботи з великими файлами
const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024; // 100 МБ
const BLOCK_SIZE: usize = 10 * 1024 * 1024; // 10 МБ

const STEGO_SIGNATURE: &[u8] = b"STEG";
const BITS_PER_BYTE: usize = 8;

#[derive(Parser, Debug, Clone)]
#[command(group = clap::ArgGroup::new("input_target")
                
                .args(&["file_path", "dir_path"]))]
struct Cli {
    /// Шлях до вхідного файлу (для encrypt, decrypt, steg-hide [секрет], steg-extract [стего-зображення])
    #[clap(short = 'f', long)] // required_if_eq_any тут не потрібен, бо є група input_target
    file_path: Option<String>, 

    /// Шлях до каталогу для обробки (для encrypt, decrypt)
    #[clap(short = 'd', long)]
    dir_path: Option<String>,

    /// Дія: encrypt, decrypt, steg-hide, steg-extract
    #[clap(short = 'a', long, required = true)]
    action: String,

    /// Алгоритм: aes-128, aes-256, chacha20
    #[clap(short = 'l', long, default_value = "aes-256")]
    algorithm: String,

    /// Шлях до файлу з ключем
    #[arg(short = 'k', long)]
    key_file: Option<String>,

    /// Шлях для збереження ключа (при шифруванні)
    #[arg(short = 'S', long)]
    save_key_path: Option<String>,

    /// Використовути пароль
    #[arg(short = 'p', long)]
    use_password: bool,

    /// Шлях для збереження вихідного файлу/каталогу
    #[clap(short = 'o', long)] // Для steg-extract цей шлях буде обов'язковим
    output: Option<String>,

    /// Шлях до зображення-контейнера (для steg-hide, буде перезаписано)
    #[clap(short = 'c', long, value_name = "COVER_IMAGE_PATH", required_if_eq("action", "steg-hide"))]
    cover_image_path: Option<String>,

    /// Увімкнути тихий режим
    #[clap(short = 's', long)]
    silent: bool,

    /// Увімкнути режим налагодження
    #[clap(short = 'v', long)]
    verbose: bool,
}



#[derive(Clone)]
struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }
    
    fn expose_secret(&self) -> &[u8] {
        &self.inner
    }
}


// Енумерація для можливих помилок програми
#[derive(Debug)]
enum CryptoError {
    IoError(io::Error),
    InvalidKeyLength(usize, usize),
    InvalidData(String),
    HashMismatch,
    DecryptionError,
    UnknownAlgorithm(String),
    HexDecodingError(hex::FromHexError),
    IntegrityCheckFailed,
    NotLargeFile,
}

impl From<io::Error> for CryptoError {
    fn from(error: io::Error) -> Self {
        CryptoError::IoError(error)
    }
}

impl From<hex::FromHexError> for CryptoError {
    fn from(error: hex::FromHexError) -> Self {
        CryptoError::HexDecodingError(error)
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::IoError(e) => write!(f, "Помилка вводу/виводу: {}", e),
            CryptoError::InvalidKeyLength(actual, expected) => {
                write!(f, "Неправильна довжина ключа: очікується {} байт, отримано {}", expected, actual)
            },
            CryptoError::InvalidData(msg) => write!(f, "Неправильні дані: {}", msg),
            CryptoError::HashMismatch => write!(f, "Хеш не збігається. Дані пошкоджені"),
            CryptoError::DecryptionError => write!(f, "Помилка дешифрування"),
            CryptoError::UnknownAlgorithm(algo) => write!(f, "Невідомий алгоритм: {}", algo),
            CryptoError::HexDecodingError(e) => write!(f, "Помилка декодування hex: {}", e),
            CryptoError::IntegrityCheckFailed => write!(f, "Перевірка цілісності файлу не пройшла. Файл може бути пошкоджений або модифікований"),
            CryptoError::NotLargeFile => write!(f, "Файл не є великим файлом"),        
        }
    }
}

impl std::error::Error for CryptoError {}

// Структура для керування виведенням повідомлень
#[derive(Clone)]
struct Logger {
    silent: bool,
    verbose: bool,
}

impl Logger {
    fn new(silent: bool, verbose: bool) -> Self {
        Logger { silent, verbose }
    }

    fn info(&self, message: &str) {
        if !self.silent {
            println!("{}", message);
        }
    }

    fn verbose(&self, message: &str) {
        if self.verbose && !self.silent {
            println!("[Детально] {}", message);
        }
    }

    fn error(&self, message: &str) {
        if !self.silent {
            eprintln!("[Помилка] {}", message);
        }
    }

    fn warn(&self, message: &str) {
    if !self.silent {
        eprintln!("[Увага] {}", message);
        }
    }
}


// Нова функція
fn save_password_protected_key_file(
    file_encryption_key: &SecretBytes, // Оригінальний FEK
    key_file_path: &str,
    logger: &Logger,
) -> Result<(), CryptoError> {
    logger.info(&format!("Захист файлу ключа '{}' паролем.", key_file_path));
    logger.info("Введіть пароль для шифрування файлу ключа:");
    let password = read_password_securely(logger)?;
    println!(); // new line after password

    let salt = generate_random_bytes(); // Сіль для PBKDF2
    logger.verbose("Згенеровано сіль для файлу ключа.");

    let derived_key_for_fek_file = derive_key_from_password(&password, &salt)?;
    logger.verbose("Ключ для шифрування файлу ключа отримано з пароля.");

    // Шифруємо сам FEK. encrypt_with_derived_key вже додає nonce.
    let encrypted_fek_payload = encrypt_with_derived_key(
        file_encryption_key.expose_secret(),
        &derived_key_for_fek_file
    )?;
    logger.verbose("FEK зашифровано для збереження у файл ключа.");

    let mut output_key_file = File::create(key_file_path).map_err(|e| {
        logger.error(&format!("Не вдалося створити файл ключа '{}': {}", key_file_path, e));
        CryptoError::IoError(e)
    })?;

    // Записуємо сіль, потім зашифрований FEK (який вже містить nonce + шифртекст + тег)
    output_key_file.write_all(&salt).map_err(|e| {
        logger.error(&format!("Помилка запису солі у файл ключа: {}", e));
        CryptoError::IoError(e)
    })?;
    output_key_file.write_all(&encrypted_fek_payload).map_err(|e| {
        logger.error(&format!("Помилка запису зашифрованого FEK у файл ключа: {}", e));
        CryptoError::IoError(e)
    })?;

    logger.info(&format!("Файл ключа '{}' успішно зашифровано паролем та збережено.", key_file_path));
    Ok(())
}

// Нова функція
fn read_and_decrypt_password_protected_key_file(
    key_file_path: &str,
    logger: &Logger,
) -> Result<SecretBytes, CryptoError> {
    logger.info(&format!("Файл ключа '{}' захищено паролем. Будь ласка, введіть пароль.", key_file_path));
    let password = read_password_securely(logger)?;
    println!(); // new line

    let mut encrypted_key_file = File::open(key_file_path).map_err(|e| {
        logger.error(&format!("Не вдалося відкрити зашифрований файл ключа '{}': {}", key_file_path, e));
        CryptoError::IoError(e)
    })?;

    let mut salt = [0u8; PBKDF2_SALT_LEN];
    encrypted_key_file.read_exact(&mut salt).map_err(|e| {
        logger.error(&format!("Помилка читання солі з файлу ключа: {}", e));
        CryptoError::IoError(e)
    })?;
    logger.verbose("Сіль з файлу ключа прочитано.");

    let mut encrypted_fek_payload = Vec::new();
    encrypted_key_file.read_to_end(&mut encrypted_fek_payload).map_err(|e| {
        logger.error(&format!("Помилка читання зашифрованого FEK з файлу ключа: {}", e));
        CryptoError::IoError(e)
    })?;
    
    if encrypted_fek_payload.len() < 12 + 16 { // Nonce + мінімальний шифртекст + тег
        logger.error("Файл ключа пошкоджено або має невірний формат (занадто короткий).");
        return Err(CryptoError::InvalidData("Зашифрований файл ключа занадто короткий".to_string()));
    }

    logger.verbose("Зашифрований FEK з файлу ключа прочитано.");

    let derived_key_for_fek_file = derive_key_from_password(&password, &salt)?;
    logger.verbose("Ключ для дешифрування файлу ключа отримано з пароля.");

    let decrypted_fek_bytes = decrypt_with_derived_key(
        &encrypted_fek_payload,
        &derived_key_for_fek_file
    )?;
    logger.verbose("FEK з файлу ключа успішно дешифровано.");



    Ok(SecretBytes::new(decrypted_fek_bytes))
}



/// Функція для збереження ключа у файл з використанням secrecy
fn save_key_to_file(key: &SecretBytes, key_file_path: &str, logger: &Logger) -> Result<(), CryptoError> {
    let mut key_file = File::create(key_file_path).map_err(|e| {
        logger.error(&format!("Не вдалося створити файл для ключа '{}': {}", key_file_path, e));
        CryptoError::IoError(e)
    })?;
    
    // Перетворення ключа в безпечне hex-представлення
    let key_hex = hex::encode(key.expose_secret());
    
    key_file.write_all(key_hex.as_bytes()).map_err(|e| {
        logger.error(&format!("Помилка запису ключа у файл: {}", e));
        CryptoError::IoError(e)
    })?;
    
    logger.info(&format!("Ключ успішно збережено у файл '{}'", key_file_path));
    Ok(())
}

/// Функція для зчитування ключа з файлу з використанням secrecy
fn read_key_from_file(key_file_path: &str, expected_len: usize, logger: &Logger) -> Result<SecretBytes, CryptoError> {
    let mut key_file = File::open(key_file_path).map_err(|e| {
        logger.error(&format!("Не вдалося відкрити файл ключа '{}': {}", key_file_path, e));
        CryptoError::IoError(e)
    })?;
    
    let mut key_hex = String::new();
    key_file.read_to_string(&mut key_hex).map_err(|e| {
        logger.error(&format!("Помилка читання ключа з файлу: {}", e));
        CryptoError::IoError(e)
    })?;
    
    let decoded_key = decode(key_hex.trim()).map_err(|e| {
        logger.error(&format!("Помилка декодування ключа з файлу: {}", e));
        CryptoError::from(e)
    })?;
    
    if decoded_key.len() != expected_len {
        logger.error(&format!(
            "Неправильна довжина ключа у файлі. Очікується {} байт ({} шістнадцяткових символів)",
            expected_len,
            expected_len * 2
        ));
        return Err(CryptoError::InvalidKeyLength(decoded_key.len(), expected_len));
    }
    
    Ok(SecretBytes::new(decoded_key))
}


/// Безпечно зчитує пароль з консолі, приховуючи введені символи.
#[cfg(target_os = "linux")]
fn read_password_securely(logger: &Logger) -> Result<SecretString, CryptoError> {
    use std::io::{self, Write};
    use getch::Getch;

    logger.verbose("[DEBUG] Використовується getch для Linux");

    let g = Getch::new();
    let mut password = String::new();

    io::stdout().flush().unwrap();

    loop {
        match g.getch() {
            Ok(key) => {
                match key {
                    3 => break, // Ctrl+C
                    10 | 13 => break, // Enter
                    8 | 127 => { // Backspace
                        if !password.is_empty() {
                            password.pop();
                            print!("\x08 \x08"); // Erase the last character in the terminal
                            io::stdout().flush().unwrap();
                        }
                    }
                    _ => {
                        password.push(key as char);
                    }
                }
            }
            Err(e) => return Err(CryptoError::IoError(e)),
        }
    }
    println!(); // Newline after password input
    Ok(SecretString::new(password.into())) // Обертаємо зчитаний пароль у SecretString
}


#[cfg(not(target_os = "linux"))]
fn read_password_securely(logger: &Logger) -> Result<SecretString, CryptoError> {
    use rpassword; // std::io::BufReader більше не потрібен тут

    logger.verbose("[DEBUG] Використовується rpassword::read_password() для інших ОС");

    match rpassword::read_password() { // Використовуємо пряму функцію
        Ok(password_string) => Ok(SecretString::new(password_string)),
        Err(e) => {
            logger.error(&format!("[Помилка] Не вдалося прочитати пароль: {}", e));
            Err(CryptoError::IoError(e))
        }
    }
}



/// Генерує випадковий ключ заданої довжини
fn generate_random_key(algorithm: &str) -> Result<SecretBytes, CryptoError> {
    let key_len = match algorithm {
        "aes-128" => 16,
        "aes-256" | "chacha20" => 32,
        _ => return Err(CryptoError::UnknownAlgorithm(algorithm.to_string())),
    };
    
    let mut key = vec![0u8; key_len];
    OsRng.fill_bytes(&mut key);
    Ok(SecretBytes::new(key))
}



/// Генерує випадкову сіль (salt)
fn generate_random_bytes() -> [u8; PBKDF2_SALT_LEN] {
    let mut salt = [0u8; PBKDF2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Отримує ключ шифрування з пароля, використовуючи PBKDF2
fn derive_key_from_password(password: &SecretString, salt: &[u8]) -> Result<SecretBytes, CryptoError> {
    let pbkdf2_algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
    let mut derived_key = vec![0u8; PBKDF2_BYTES];

    pbkdf2::derive(
        pbkdf2_algorithm,
        std::num::NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        salt,
        password.expose_secret().as_bytes(), // Отримуємо доступ до пароля як &[u8] 
        &mut derived_key,
    );
   
    Ok(SecretBytes::new(derived_key))
}

/// Шифрує дані (наш випадковий ключ) за допомогою ключа, отриманого з пароля
fn encrypt_with_derived_key(data: &[u8], derived_key: &SecretBytes) -> Result<Vec<u8>, CryptoError> {
    let nonce = generate_random_nonce();
    
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, derived_key.expose_secret())
        .map_err(|_| CryptoError::InvalidData("Невірний ключ для AES-256 (отриманий з PBKDF2)".to_string()))?;
    
    let less_safe_key = aead::LessSafeKey::new(unbound_key);
    let mut in_out = data.to_vec();
    
    less_safe_key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce), 
        aead::Aad::empty(), 
        &mut in_out
    ).map_err(|_| CryptoError::InvalidData("Помилка шифрування ключа".to_string()))?;

    let mut encrypted_with_nonce = nonce.to_vec();
    encrypted_with_nonce.extend_from_slice(&in_out);
    
    Ok(encrypted_with_nonce)
}

/// Дешифрує дані (наш випадковий ключ), зашифровані за допомогою ключа, отриманого з пароля
fn decrypt_with_derived_key(encrypted_data: &[u8], derived_key: &SecretBytes) -> Result<Vec<u8>, CryptoError> {
    if encrypted_data.len() < 12 {
        return Err(CryptoError::InvalidData("Зашифровані дані ключа занадто короткі".to_string()));
    }
    
    let nonce = &encrypted_data[..12];
    let encrypted_payload = &encrypted_data[12..];

    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, derived_key.expose_secret())
        .map_err(|_| CryptoError::InvalidData("Невірний ключ для AES-256 (отриманий з PBKDF2)".to_string()))?;
    
    let less_safe_key = aead::LessSafeKey::new(unbound_key);
    let mut in_out = encrypted_payload.to_vec();

    let decrypted_bytes = less_safe_key.open_in_place(
        aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap()),
        aead::Aad::empty(),
        &mut in_out,
    ).map_err(|_| CryptoError::DecryptionError)?;

    // Повертаємо тільки розшифровані дані без тегу
    Ok(decrypted_bytes.to_vec())
}

/// Перевіряє хеш
fn validate_hash(data: &[u8], expected_hash: &[u8]) -> bool {
    let calculated_hash = calculate_hash(data);
    calculated_hash == expected_hash
}

/// Витягає метадані та хеш
fn extract_metadata_with_hash(data: &[u8]) -> Result<(usize, Vec<u8>, &[u8]), CryptoError> {
    if data.len() < 8 {
        return Err(CryptoError::InvalidData("Недостатньо даних для витягу метаданих".to_string()));
    }
    
    let size_bytes = &data[..8];
    let original_size = u64::from_le_bytes(size_bytes.try_into().unwrap()) as usize;

    if data.len() < 8 + 32 {
        return Err(CryptoError::InvalidData("Недостатньо даних для витягу хешу".to_string()));
    }
    
    let hash = &data[8..8 + 32];
    let valid_data = &data[8 + 32..];

    Ok((original_size, hash.to_vec(), valid_data))
}

/// Генерація хешу SHA-256
fn calculate_hash(data: &[u8]) -> Vec<u8> {
    let digest = digest::digest(&digest::SHA256, data);
    digest.as_ref().to_vec()
}


/// Функція для генерації випадкового nonce для AEAD шифрування
fn generate_random_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let rng = ring::rand::SystemRandom::new();
    rng.fill(&mut nonce).expect("Помилка генерації випадкового nonce");
    nonce
}


/// Шифрування даних
fn encrypt_data(data: &[u8], key: &[u8], algorithm: &str, original_size: usize, hash: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut data_with_metadata = original_size.to_le_bytes().to_vec();
    data_with_metadata.extend_from_slice(hash);
    data_with_metadata.extend_from_slice(data);

    let nonce = generate_random_nonce();

    let unbound_key = match algorithm {
        "aes-128" => aead::UnboundKey::new(&aead::AES_128_GCM, key)
            .map_err(|_| CryptoError::InvalidData("Помилка створення ключа для AES-128".to_string()))?,
        "aes-256" => aead::UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|_| CryptoError::InvalidData("Помилка створення ключа для AES-256".to_string()))?,
        "chacha20" => aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)
            .map_err(|_| CryptoError::InvalidData("Помилка створення ключа для ChaCha20".to_string()))?,
        _ => return Err(CryptoError::UnknownAlgorithm(algorithm.to_string())),
    };

    let less_safe_key = aead::LessSafeKey::new(unbound_key);
    let mut in_out = data_with_metadata;
    
    less_safe_key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce), 
        aead::Aad::empty(), 
        &mut in_out
    ).map_err(|_| CryptoError::InvalidData("Помилка шифрування даних".to_string()))?;

    let mut encrypted_with_nonce = nonce.to_vec();
    encrypted_with_nonce.extend_from_slice(&in_out);
    
    Ok(encrypted_with_nonce)
}

/// Дешифрування даних
fn decrypt_data(encrypted_data: &[u8], key: &[u8], algorithm: &str, logger: &Logger) -> Result<Vec<u8>, CryptoError> {
    let nonce_len = 12;
    if encrypted_data.len() < nonce_len + 16 {
        return Err(CryptoError::InvalidData("Зашифровані дані занадто короткі".to_string()));
    }
    
    let nonce = &encrypted_data[..nonce_len];
    let cipher_text_with_tag = &encrypted_data[nonce_len..];
    logger.verbose(&format!("[Детально у decrypt_data] Довжина encrypted_data: {}", encrypted_data.len()));
    logger.verbose(&format!("[Детально у decrypt_data] Nonce: {:x?}", nonce));
    logger.verbose(&format!("[Детально у decrypt_data] Cipher text with tag довжина: {}", cipher_text_with_tag.len()));
    logger.verbose(&format!("[Детально у decrypt_data] Ключ для дешифрування даних: {:x?}", key));
    logger.verbose(&format!("[Детально у decrypt_data] Алгоритм: {}", algorithm));
    let unbound_key = match algorithm {
        "aes-128" => aead::UnboundKey::new(&aead::AES_128_GCM, key)
            .map_err(|_| CryptoError::InvalidData("Помилка створення ключа для AES-128".to_string()))?,
        "aes-256" => aead::UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|_| CryptoError::InvalidData("Помилка створення ключа для AES-256".to_string()))?,
        "chacha20" => aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)
            .map_err(|_| CryptoError::InvalidData("Помилка створення ключа для ChaCha20".to_string()))?,
        _ => return Err(CryptoError::UnknownAlgorithm(algorithm.to_string())),
    };

    let less_safe_key = aead::LessSafeKey::new(unbound_key);
    let mut in_out = cipher_text_with_tag.to_vec();

    let decrypted_bytes = less_safe_key.open_in_place(
        aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap()),
        aead::Aad::empty(),
        &mut in_out,
    ).map_err(|_| CryptoError::DecryptionError)?;

    Ok(decrypted_bytes.to_vec())
}


/// Функція шифрування файлу
fn encrypt_file(
    file_path: &str,
    algorithm: &str,
    output_path: &Option<String>,
    logger: &Logger,
    cli_args: &Cli,
) -> Result<(), CryptoError> {
    let output_file_path = match output_path {
        Some(path) => path.clone(),
        None => format!("{}.enc", file_path),
    };
    logger.info(&format!("Шифрування файлу '{}'", file_path));
    logger.verbose(&format!("Використовується алгоритм '{}'", algorithm));

    let mut input_file_data = Vec::new();
    File::open(file_path)?.read_to_end(&mut input_file_data)?;
    logger.verbose("Файл прочитано");

    let key_management_flag: u8; 
    let mut salt_for_main_file: Option<[u8; PBKDF2_SALT_LEN]> = None;
    let mut encrypted_fek_for_main_file_storage: Option<Vec<u8>> = None;
    
    // Визначаємо FEK (File Encryption Key)
    let fek: SecretBytes = if let Some(key_file_path_arg) = &cli_args.key_file {
        logger.verbose(&format!("Спроба використання ключа з файлу '{}'", key_file_path_arg));
        let expected_key_len = match algorithm {
            "aes-128" => 16,
            "aes-256" | "chacha20" => 32,
            _ => return Err(CryptoError::UnknownAlgorithm(algorithm.to_string())),
        };

        match read_key_from_file(key_file_path_arg, expected_key_len, logger) {
            Ok(plain_fek) => {
                logger.verbose(&format!("Ключ успішно прочитано з файлу '{}' (як відкритий/hex).", key_file_path_arg));
                key_management_flag = KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE;
                if cli_args.use_password {
                    logger.warn("Прапорець -p (пароль) ігнорується, оскільки ключ з -k успішно прочитано як відкритий.");
                }
                if cli_args.save_key_path.is_some() {
                    logger.warn("Прапорець -S (зберегти ключ) ігнорується, оскільки ключ надано через -k.");
                }
                plain_fek
            }
            Err(e_plain) => {
                logger.verbose(&format!("Не вдалося прочитати ключ з '{}' як відкритий/hex (Помилка: {}). Спроба прочитати як зашифрований паролем файл ключа.", key_file_path_arg, e_plain));
                match read_and_decrypt_password_protected_key_file(key_file_path_arg, logger) {
                    Ok(decrypted_fek) => {
                        if decrypted_fek.expose_secret().len() != expected_key_len {
                            logger.error(&format!(
                                "Довжина ключа ({}), дешифрованого з файлу '{}', не відповідає очікуваній ({}) для алгоритму '{}'.",
                                decrypted_fek.expose_secret().len(), key_file_path_arg, expected_key_len, algorithm
                            ));
                            return Err(CryptoError::InvalidKeyLength(decrypted_fek.expose_secret().len(), expected_key_len));
                        }
                        logger.verbose(&format!("Ключ успішно дешифровано з файлу '{}' за допомогою пароля.", key_file_path_arg));
                        key_management_flag = KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE; // FEK "готовий до використання"
                        if cli_args.save_key_path.is_some() {
                            logger.warn("Прапорець -S (зберегти ключ) ігнорується, оскільки ключ надано через -k (і успішно дешифровано).");
                        }
                        decrypted_fek
                    }
                    Err(e_encrypted) => {
                        logger.error(&format!("Не вдалося прочитати ключ з файлу '{}' ані як відкритий (Помилка: {}), ані як зашифрований паролем (Помилка: {}).", key_file_path_arg, e_plain, e_encrypted));
                        return Err(CryptoError::InvalidData(format!("Не вдалося обробити файл ключа '{}'. Перевірте формат файлу або пароль.", key_file_path_arg)));
                    }
                }
            }
        }
    } else {
        // Існуюча логіка генерації нового FEK
        logger.verbose("Генерація нового випадкового ключа для шифрування файлу.");
        let generated_fek = generate_random_key(algorithm)?;

        if let Some(save_key_to_path) = &cli_args.save_key_path {
            if cli_args.use_password {
                save_password_protected_key_file(&generated_fek, save_key_to_path, logger)?;
                key_management_flag = KEY_MANAGEMENT_FLAG_ENCRYPTED_KEY_FILE; // Новий файл ключа створено, він зашифрований
            } else {
                save_key_to_file(&generated_fek, save_key_to_path, logger)?;
                key_management_flag = KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE; // Новий файл ключа створено, він відкритий
            }
        } else {
            if cli_args.use_password {
                 logger.verbose("Явно вказано використання пароля (-p). Ключ буде зашифровано та збережено в основному файлі.");
            } else {
                 logger.verbose("За замовчуванням (не вказано -k або -S): ключ буде зашифровано паролем та збережено в основному файлі.");
            }
             logger.info("Введіть пароль:");
             let password = read_password_securely(logger)?;
             println!();
             let salt = generate_random_bytes();
             salt_for_main_file = Some(salt);
             let derived_key = derive_key_from_password(&password, &salt)?;
             encrypted_fek_for_main_file_storage = Some(encrypt_with_derived_key(generated_fek.expose_secret(), &derived_key)?);
             key_management_flag = KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE; // FEK вбудовано в основний файл
        }
        generated_fek // Використовуємо згенерований ключ
    };

    logger.verbose("Розрахунок хешу вхідних даних");
    let hash = calculate_hash(&input_file_data);
    logger.verbose("Шифрування даних файлу");
    let encrypted_data_payload = encrypt_data(
        &input_file_data,
        fek.expose_secret(), 
        algorithm,
        input_file_data.len(),
        &hash
    )?;
    logger.verbose("Дані файлу зашифровано");

    let mut output_file = File::create(&output_file_path).map_err(|e| {
        logger.error(&format!("Помилка створення вихідного файлу '{}': {}", output_file_path, e));
        CryptoError::IoError(e)
    })?;
    let algorithm_code = match algorithm {
        "aes-128" => 0x01u8, "aes-256" => 0x02u8, "chacha20" => 0x03u8,
        _ => return Err(CryptoError::UnknownAlgorithm(algorithm.to_string())),
    };
    output_file.write_all(&[algorithm_code])?;
    output_file.write_all(&[key_management_flag])?; // Використовуємо визначений key_management_flag

    if key_management_flag == KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE {
        if let Some(salt) = salt_for_main_file {
            output_file.write_all(&salt)?;
        } else {
            return Err(CryptoError::InvalidData("Внутрішня помилка: сіль для основного файлу відсутня.".to_string()));
        }
        if let Some(enc_fek) = encrypted_fek_for_main_file_storage {
            let len_bytes = (enc_fek.len() as u32).to_le_bytes(); 
            output_file.write_all(&len_bytes)?;
            output_file.write_all(&enc_fek)?;
        } else {
             return Err(CryptoError::InvalidData("Внутрішня помилка: зашифрований FEK для основного файлу відсутній.".to_string()));
        }
    }
    
    output_file.write_all(&encrypted_data_payload)?;
    logger.info(&format!("Файл успішно зашифровано та збережено як '{}'", output_file_path));
    Ok(())
}


    
/// Функція дешифрування файлу
fn decrypt_file(
    file_path: &str,
    provided_algorithm_cli: &str, // Алгоритм з командного рядка
    output_path: &Option<String>,
    logger: &Logger,
    cli_args: &Cli,
) -> Result<(), CryptoError> {
    let output_file_path = match output_path {
        Some(path) => path.clone(),
        None => format!("{}.dec", file_path),
    };
    logger.info(&format!("Дешифрування файлу '{}'", file_path));

    let mut encrypted_file = File::open(file_path)?;

    let mut algorithm_code_buffer = [0u8; 1];
    encrypted_file.read_exact(&mut algorithm_code_buffer)?;
    let algorithm_from_file_code = algorithm_code_buffer[0];
    let algorithm_from_file = match algorithm_from_file_code {
        0x01 => "aes-128", 0x02 => "aes-256", 0x03 => "chacha20",
        _ => return Err(CryptoError::InvalidData(format!("Невідомий код алгоритму: 0x{:02x}", algorithm_from_file_code))),
    };

    if !provided_algorithm_cli.is_empty() && provided_algorithm_cli != algorithm_from_file {
        logger.verbose(&format!(
            "Увага: Наданий алгоритм '{}' буде проігноровано, використовується алгоритм з файлу: '{}'",
            provided_algorithm_cli, algorithm_from_file
        ));
    }
    logger.verbose(&format!("Визначено алгоритм з файлу: '{}'", algorithm_from_file));
    let algorithm_to_use = algorithm_from_file;

    let mut key_management_flag_buffer = [0u8; 1];
    encrypted_file.read_exact(&mut key_management_flag_buffer)?;
    let key_management_flag = key_management_flag_buffer[0];

    let fek: SecretBytes;

    match key_management_flag {
        KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE => {
            logger.verbose("Файл вказує на використання ключа з файлу (-k). Спроба читання...");
            if let Some(key_file_path) = &cli_args.key_file {
                let expected_key_len = match algorithm_to_use {
                    "aes-128" => 16, "aes-256" | "chacha20" => 32,
                    _ => return Err(CryptoError::UnknownAlgorithm(algorithm_to_use.to_string())),
                };

                match read_key_from_file(key_file_path, expected_key_len, logger) {
                    Ok(plain_fek) => {
                        logger.verbose(&format!("Ключ з файлу '{}' успішно прочитано як відкритий/hex.", key_file_path));
                        fek = plain_fek;
                    }
                    Err(e_plain) => {
                        logger.verbose(&format!("Не вдалося прочитати ключ з '{}' як відкритий/hex (Помилка: {}). Спроба прочитати як зашифрований паролем файл ключа.", key_file_path, e_plain));
                        match read_and_decrypt_password_protected_key_file(key_file_path, logger) { //
                            Ok(decrypted_fek) => {
                                if decrypted_fek.expose_secret().len() != expected_key_len {
                                    logger.error(&format!(
                                        "Довжина ключа ({}), дешифрованого з файлу '{}', не відповідає очікуваній ({}) для алгоритму '{}'.",
                                        decrypted_fek.expose_secret().len(), key_file_path, expected_key_len, algorithm_to_use
                                    ));
                                    return Err(CryptoError::InvalidKeyLength(decrypted_fek.expose_secret().len(), expected_key_len));
                                }
                                logger.verbose(&format!("Ключ успішно дешифровано з файлу '{}' за допомогою пароля.", key_file_path));
                                fek = decrypted_fek;
                            }
                            Err(e_encrypted) => {
                                logger.error(&format!("Не вдалося прочитати ключ з файлу '{}' ані як відкритий (Помилка: {}), ані як зашифрований паролем (Помилка: {}).", key_file_path, e_plain, e_encrypted));
                                return Err(CryptoError::InvalidData(format!("Не вдалося обробити файл ключа '{}'. Перевірте формат файлу або пароль.", key_file_path)));
                            }
                        }
                    }
                }
            } else {
                return Err(CryptoError::InvalidData("Файл зашифровано з використанням файлу ключа (-k), але шлях до файлу ключа не надано.".to_string())); //
            }
        }
        KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE => {
            logger.verbose("Ключ зашифровано паролем і зберігається в основному файлі."); //
            if !cli_args.use_password && cli_args.key_file.is_some() { //
                 logger.error("Файл вказує на використання пароля, але надано ключ-файл (-k) замість прапорця -p.");
                 return Err(CryptoError::InvalidData("Невідповідність: файл очікує пароль, а надано ключ-файл.".to_string()));
            }
            
            let mut salt = [0u8; PBKDF2_SALT_LEN]; // [cite: 4, 139]
            encrypted_file.read_exact(&mut salt)?; // [cite: 139]
            logger.verbose("Сіль прочитано з основного файлу."); // [cite: 140]

            let mut len_bytes = [0u8; 4]; //
            encrypted_file.read_exact(&mut len_bytes)?; // [cite: 141]
            let enc_fek_len = u32::from_le_bytes(len_bytes) as usize; // [cite: 141]

            let mut encrypted_fek_from_main_file = vec![0u8; enc_fek_len]; // [cite: 141]
            encrypted_file.read_exact(&mut encrypted_fek_from_main_file)?; // [cite: 141]
            logger.verbose("Зашифрований FEK прочитано з основного файлу."); // [cite: 142]

            logger.info("Введіть пароль для дешифрування ключа:"); // [cite: 142]
            let password = read_password_securely(logger)?; // [cite: 142]
            println!(); // [cite: 142]
            let derived_key = derive_key_from_password(&password, &salt)?; // [cite: 143]
            
            let decrypted_bytes = decrypt_with_derived_key(&encrypted_fek_from_main_file, &derived_key)?; // [cite: 143]
            fek = SecretBytes::new(decrypted_bytes); // [cite: 143]
        }
        KEY_MANAGEMENT_FLAG_ENCRYPTED_KEY_FILE => {
            logger.verbose("Ключ зберігається в окремому файлі, який зашифровано паролем."); // [cite: 144]
            if let Some(key_file_path) = &cli_args.key_file {
                let decrypted_fek_candidate = read_and_decrypt_password_protected_key_file(key_file_path, logger)?; // [cite: 145]
                
                // Додано перевірку довжини ключа тут
                let expected_key_len = match algorithm_to_use {
                     "aes-128" => 16, "aes-256" | "chacha20" => 32,
                    _ => return Err(CryptoError::UnknownAlgorithm(algorithm_to_use.to_string())),
                };
                if decrypted_fek_candidate.expose_secret().len() != expected_key_len {
                    logger.error(&format!(
                        "Довжина ключа ({}), дешифрованого з файлу '{}' (тип ENCRYPTED_KEY_FILE), не відповідає очікуваній ({}) для алгоритму '{}'.",
                        decrypted_fek_candidate.expose_secret().len(), key_file_path, expected_key_len, algorithm_to_use
                    ));
                    return Err(CryptoError::InvalidKeyLength(decrypted_fek_candidate.expose_secret().len(), expected_key_len));
                }
                fek = decrypted_fek_candidate;
            } else {
                 return Err(CryptoError::InvalidData("Файл зашифровано з використанням зашифрованого файлу ключа (-k), але шлях до файлу ключа не надано.".to_string())); //
            }
        }
        _ => {
            return Err(CryptoError::InvalidData(format!("Невідомий прапор управління ключем: {}", key_management_flag))); //
        }
    }

    let expected_fek_len = match algorithm_to_use {
        "aes-128" => 16, "aes-256" | "chacha20" => 32, //
        _ => unreachable!(), 
    };
    if fek.expose_secret().len() != expected_fek_len { // [cite: 150]
        logger.error(&format!( // [cite: 150]
            "Неправильна довжина дешифрованого ключа FEK. Очікується {} байт, отримано {}.",
            expected_fek_len, fek.expose_secret().len()
        ));
        return Err(CryptoError::InvalidKeyLength(fek.expose_secret().len(), expected_fek_len)); // [cite: 151]
    }
    logger.verbose("FEK успішно отримано та перевірено на довжину."); // [cite: 151]
    
    let mut encrypted_data_payload = Vec::new(); // [cite: 152]
    encrypted_file.read_to_end(&mut encrypted_data_payload)?; // [cite: 152]
    logger.verbose(&format!("Прочитано {} байт основних зашифрованих даних", encrypted_data_payload.len())); // [cite: 153]

    logger.verbose("Дешифрування основних даних файлу"); // [cite: 153]
    let decrypted_with_original_metadata = decrypt_data( // [cite: 154]
        &encrypted_data_payload,
        fek.expose_secret(),
        algorithm_to_use,
        logger
    )?;
    logger.verbose("Дані файлу дешифровано"); // [cite: 156]
    logger.verbose(&format!("Довжина дешифрованих з метаданими даних: {} байт", decrypted_with_original_metadata.len())); // [cite: 156]
    
    logger.verbose("Витягування метаданих та перевірка хешу"); // [cite: 156]
    let (original_size, expected_hash, decrypted_data_content) = extract_metadata_with_hash(&decrypted_with_original_metadata)?; // [cite: 157]
    logger.verbose(&format!("Оригінальний розмір даних: {} байт", original_size)); // [cite: 157]
    logger.verbose(&format!("Отриманий хеш: {:x?}", expected_hash)); // [cite: 157]
    logger.verbose(&format!("Довжина дешифрованих даних без метаданих: {} байт", decrypted_data_content.len())); // [cite: 158]
    
    let calculated_hash = calculate_hash(decrypted_data_content); // [cite: 158]
    logger.verbose(&format!("Розрахований хеш: {:x?}", calculated_hash)); // [cite: 158]
    if !validate_hash(decrypted_data_content, &expected_hash) { // [cite: 159]
        logger.error("Помилка: Хеш дешифрованих даних не збігається з очікуваним. Можливо, дані пошкоджено або ключ неправильний."); // [cite: 159]
        return Err(CryptoError::HashMismatch); // [cite: 160]
    }
    logger.verbose("Хеш успішно перевірено"); // [cite: 160]

    let final_decrypted_data = &decrypted_data_content[..original_size]; // [cite: 160]
    logger.verbose(&format!("Кінцева довжина дешифрованих даних: {} байт", final_decrypted_data.len())); // [cite: 160]
    let mut output_decrypted_file = File::create(&output_file_path)?; // [cite: 161]
    output_decrypted_file.write_all(final_decrypted_data)?; // [cite: 161]

    logger.info(&format!("Файл успішно дешифровано та збережено як '{}'", output_file_path)); // [cite: 161]
    Ok(())
}

/// Перевіряє, чи є файл великим (більше 100 МБ)
fn is_large_file(file_path: &str, logger: &Logger) -> Result<bool, CryptoError> { // НОВА ВЕРСІЯ
    let metadata = std::fs::metadata(file_path).map_err(|e| {
        // Використовуємо logger тут
        logger.error(&format!("Не вдалося отримати метадані для файлу '{}' у is_large_file: {}", file_path, e));
        CryptoError::IoError(e)
    })?;
    Ok(metadata.len() > LARGE_FILE_THRESHOLD)
}

/// Шифрування великого файлу блоками по 10 МБ
fn encrypt_large_file(
    file_path: &str,
    algorithm: &str, // Алгоритм шифрування файлу
    output_path: &Option<String>,
    logger: &Logger,
    cli_args: &Cli,
) -> Result<(), CryptoError> {
    let output_file_path = match output_path {
        Some(path) => path.clone(),
        None => format!("{}.enc", file_path),
    };
    logger.info(&format!("Шифрування великого файлу '{}' блоками", file_path));
    logger.verbose(&format!("Використовується алгоритм '{}'", algorithm));
    logger.verbose(&format!("Розмір блоку: {} байт", BLOCK_SIZE)); // BLOCK_SIZE з констант [cite: 6]

    let mut input_file = File::open(file_path).map_err(|e| {
        logger.error(&format!("Не вдалося відкрити файл '{}': {}", file_path, e));
        CryptoError::IoError(e)
    })?;
    let file_size = input_file.metadata().map_err(|e| {
        logger.error(&format!("Не вдалося отримати метадані файлу: {}", e));
        CryptoError::IoError(e)
    })?.len();

    let key_management_flag: u8; 
    let mut salt_for_main_file_storage: Option<[u8; PBKDF2_SALT_LEN]> = None;
    let mut encrypted_fek_for_main_file_storage: Option<Vec<u8>> = None;

    let fek: SecretBytes = if let Some(key_file_path_arg) = &cli_args.key_file { // [cite: 169]
        logger.verbose(&format!("Спроба використання ключа з файлу '{}'", key_file_path_arg));
        let expected_key_len = match algorithm { // [cite: 170]
            "aes-128" => 16, // [cite: 170]
            "aes-256" | "chacha20" => 32, // [cite: 170, 171]
            _ => return Err(CryptoError::UnknownAlgorithm(algorithm.to_string())), // [cite: 171]
        };

        match read_key_from_file(key_file_path_arg, expected_key_len, logger) { // [cite: 172]
            Ok(plain_fek) => {
                logger.verbose(&format!("Ключ успішно прочитано з файлу '{}' (як відкритий/hex).", key_file_path_arg));
                key_management_flag = KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE; // [cite: 172]
                if cli_args.use_password { // [cite: 173]
                    logger.warn("Прапорець -p (пароль) ігнорується, оскільки ключ з -k успішно прочитано як відкритий.");
                }
                if cli_args.save_key_path.is_some() { // [cite: 172]
                    logger.warn("Прапорець -S (зберегти ключ) ігнорується, оскільки ключ надано через -k.");
                }
                plain_fek // [cite: 174]
            }
            Err(e_plain) => {
                logger.verbose(&format!("Не вдалося прочитати ключ з '{}' як відкритий/hex (Помилка: {}). Спроба прочитати як зашифрований паролем файл ключа.", key_file_path_arg, e_plain));
                match read_and_decrypt_password_protected_key_file(key_file_path_arg, logger) {
                    Ok(decrypted_fek) => {
                        if decrypted_fek.expose_secret().len() != expected_key_len {
                            logger.error(&format!(
                                "Довжина ключа ({}), дешифрованого з файлу '{}', не відповідає очікуваній ({}) для алгоритму '{}'.",
                                decrypted_fek.expose_secret().len(), key_file_path_arg, expected_key_len, algorithm
                            ));
                            return Err(CryptoError::InvalidKeyLength(decrypted_fek.expose_secret().len(), expected_key_len));
                        }
                        logger.verbose(&format!("Ключ успішно дешифровано з файлу '{}' за допомогою пароля.", key_file_path_arg));
                        key_management_flag = KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE;
                        if cli_args.save_key_path.is_some() {
                             logger.warn("Прапорець -S (зберегти ключ) ігнорується, оскільки ключ надано через -k (і успішно дешифровано).");
                        }
                        decrypted_fek
                    }
                    Err(e_encrypted) => {
                        logger.error(&format!("Не вдалося прочитати ключ з файлу '{}' ані як відкритий (Помилка: {}), ані як зашифрований паролем (Помилка: {}).", key_file_path_arg, e_plain, e_encrypted));
                        return Err(CryptoError::InvalidData(format!("Не вдалося обробити файл ключа '{}'. Перевірте формат файлу або пароль.", key_file_path_arg)));
                    }
                }
            }
        }
    } else {
        logger.verbose("Генерація нового випадкового ключа для шифрування файлу."); // [cite: 174]
        let generated_fek = generate_random_key(algorithm)?; // [cite: 175]

        if let Some(save_key_to_path_arg) = &cli_args.save_key_path { // [cite: 175]
            if cli_args.use_password { // [cite: 175]
                save_password_protected_key_file(&generated_fek, save_key_to_path_arg, logger)?;
                key_management_flag = KEY_MANAGEMENT_FLAG_ENCRYPTED_KEY_FILE; // [cite: 176]
            } else {
                save_key_to_file(&generated_fek, save_key_to_path_arg, logger)?;
                key_management_flag = KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE; // [cite: 177]
            }
        } else { 
            if cli_args.use_password { // [cite: 177]
                logger.verbose("Явно вказано використання пароля (-p). Ключ буде зашифровано та збережено в основному файлі.");
            } else { 
                logger.verbose("За замовчуванням (не вказано -k або -S): ключ буде зашифровано паролем та збережено в основному файлі."); // [cite: 178]
            }
            logger.info("Введіть пароль:"); // [cite: 179]
            let password = read_password_securely(logger)?; // [cite: 179]
            println!(); // [cite: 179]
            let salt = generate_random_bytes(); // [cite: 180]
            salt_for_main_file_storage = Some(salt); // [cite: 180]
            let derived_key = derive_key_from_password(&password, &salt)?; // [cite: 180]
            encrypted_fek_for_main_file_storage = Some(encrypt_with_derived_key(generated_fek.expose_secret(), &derived_key)?); // [cite: 180]
            key_management_flag = KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE; // [cite: 180]
        }
        generated_fek // [cite: 181]
    };

    let mut output_file = File::create(&output_file_path).map_err(|e| {
        logger.error(&format!("Помилка створення вихідного файлу '{}': {}", output_file_path, e));
        CryptoError::IoError(e)
    })?;
    
    let algorithm_code = match algorithm { // [cite: 183]
        "aes-128" => 0x01u8,
        "aes-256" => 0x02u8,
        "chacha20" => 0x03u8,
        _ => return Err(CryptoError::UnknownAlgorithm(algorithm.to_string())),
    };
    output_file.write_all(&[algorithm_code])?; // [cite: 184]
    output_file.write_all(&[key_management_flag])?; // [cite: 184]
    output_file.write_all(&[2u8])?; // Прапор блочного шифрування для великого файлу [cite: 184]
    output_file.write_all(&(file_size as u64).to_le_bytes())?; // [cite: 185]

    if key_management_flag == KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE { // [cite: 186]
        if let Some(salt) = salt_for_main_file_storage { // [cite: 186]
            output_file.write_all(&salt)?; // [cite: 186]
        } else {
            return Err(CryptoError::InvalidData("Внутрішня помилка: сіль для основного файлу (великого) відсутня.".to_string())); // [cite: 187]
        }
        if let Some(enc_fek) = encrypted_fek_for_main_file_storage { // [cite: 188]
            let len_bytes = (enc_fek.len() as u32).to_le_bytes(); // [cite: 188]
            output_file.write_all(&len_bytes)?; // [cite: 189]
            output_file.write_all(&enc_fek)?; // [cite: 189]
        } else {
             return Err(CryptoError::InvalidData("Внутрішня помилка: зашифрований FEK для основного файлу (великого) відсутній.".to_string())); // [cite: 189]
        }
    }
    
    let mut buffer = vec![0u8; BLOCK_SIZE]; // [cite: 190, 191]
    let mut remaining_bytes = file_size; // [cite: 191]
    let mut total_bytes_processed: u64 = 0; // [cite: 191]
    let mut hash_context = digest::Context::new(&digest::SHA256); // [cite: 191]

    while remaining_bytes > 0 { // [cite: 192]
        let current_block_size = std::cmp::min(BLOCK_SIZE as u64, remaining_bytes) as usize; // [cite: 192]
        input_file.read_exact(&mut buffer[..current_block_size]).map_err(|e| { // [cite: 193]
            logger.error(&format!("Помилка читання блоку даних з файлу: {}", e));
            CryptoError::IoError(e)
        })?;
        hash_context.update(&buffer[..current_block_size]); // [cite: 194]
        
        let nonce = generate_random_nonce(); // [cite: 194]
        let unbound_key = match algorithm { // [cite: 194]
            "aes-128" => aead::UnboundKey::new(&aead::AES_128_GCM, fek.expose_secret()), // [cite: 194]
            "aes-256" => aead::UnboundKey::new(&aead::AES_256_GCM, fek.expose_secret()), // [cite: 194]
            "chacha20" => aead::UnboundKey::new(&aead::CHACHA20_POLY1305, fek.expose_secret()), // [cite: 194]
            _ => unreachable!(), 
        }.map_err(|_| CryptoError::InvalidData(format!("Помилка створення ключа для {} при шифруванні блоку", algorithm)))?;
        let less_safe_key = aead::LessSafeKey::new(unbound_key); // [cite: 195]
        let mut in_out = buffer[..current_block_size].to_vec(); // [cite: 195]
        
        less_safe_key.seal_in_place_append_tag( // [cite: 195]
            aead::Nonce::assume_unique_for_key(nonce), 
            aead::Aad::empty(), 
            &mut in_out
        ).map_err(|_| CryptoError::InvalidData("Помилка шифрування блоку даних".to_string()))?;
        let encrypted_block_payload_len = in_out.len() as u32; // [cite: 196]
        output_file.write_all(&encrypted_block_payload_len.to_le_bytes())?; // [cite: 196]
        output_file.write_all(&nonce)?; // [cite: 196]
        output_file.write_all(&in_out)?; // [cite: 197]
        
        remaining_bytes -= current_block_size as u64; // [cite: 197]
        total_bytes_processed += current_block_size as u64; // [cite: 197]
        if total_bytes_processed % (100 * 1024 * 1024) < BLOCK_SIZE as u64 || remaining_bytes == 0 { // [cite: 198, 199]
             let progress = (total_bytes_processed as f64 / file_size as f64) * 100.0; // [cite: 199]
             logger.info(&format!("Прогрес: {:.2}% ({}/{} байт)", progress, total_bytes_processed, file_size)); // [cite: 200]
        }
    }

    let final_hash = hash_context.finish(); // [cite: 200]
    output_file.write_all(final_hash.as_ref()).map_err(|e| { // [cite: 201]
        logger.error(&format!("Помилка запису хешу файлу: {}", e));
        CryptoError::IoError(e)
    })?;
    logger.info(&format!("Файл успішно зашифровано та збережено як '{}'", output_file_path)); // [cite: 202]
    Ok(())
}

/// Дешифрування великого файлу блоками по 10 МБ
fn decrypt_large_file(
    file_path: &str,
    provided_algorithm_cli: &str, 
    output_path: &Option<String>,
    logger: &Logger,
    cli_args: &Cli,
) -> Result<(), CryptoError> {
    let output_file_path = match output_path {
        Some(path) => path.clone(),
        None => format!("{}.dec", file_path),
    };
    logger.info(&format!("Дешифрування великого файлу '{}' блоками", file_path)); // [cite: 204]

    let mut encrypted_file = File::open(file_path).map_err(|e| { // [cite: 204]
        logger.error(&format!("Не вдалося відкрити зашифрований файл '{}': {}", file_path, e));
        CryptoError::IoError(e)
    })?;
    
    let mut algorithm_code_buffer = [0u8; 1]; // [cite: 205]
    encrypted_file.read_exact(&mut algorithm_code_buffer)?; // [cite: 205]
    let algorithm_from_file_code = algorithm_code_buffer[0]; // [cite: 206]

    let mut key_management_flag_buffer = [0u8; 1]; // [cite: 206]
    encrypted_file.read_exact(&mut key_management_flag_buffer)?; // [cite: 206]
    let key_management_flag = key_management_flag_buffer[0]; // [cite: 207]

    let mut large_file_flag_buffer = [0u8; 1]; // [cite: 207]
    encrypted_file.read_exact(&mut large_file_flag_buffer)?; // [cite: 207]
    if large_file_flag_buffer[0] != 2 { // [cite: 208]
        logger.error("Файл не позначено як великий файл, шифрований блоками.");
        return Err(CryptoError::InvalidData("Невірний формат файлу: не є великим файлом, шифрованим блоками.".to_string())); // [cite: 209]
    }

    let mut size_bytes = [0u8; 8]; // [cite: 209]
    encrypted_file.read_exact(&mut size_bytes)?; // [cite: 210]
    let original_file_size = u64::from_le_bytes(size_bytes); // [cite: 210]

    let algorithm_from_file = match algorithm_from_file_code { // [cite: 210]
        0x01 => "aes-128", 0x02 => "aes-256", 0x03 => "chacha20",
        _ => return Err(CryptoError::InvalidData(format!("Невідомий код алгоритму у файлі: 0x{:02x}", algorithm_from_file_code))),
    };
    if !provided_algorithm_cli.is_empty() && provided_algorithm_cli != algorithm_from_file { // [cite: 211]
        logger.verbose(&format!( // [cite: 211]
            "Увага: Наданий алгоритм '{}' буде проігноровано, використовується алгоритм з файлу: '{}'",
            provided_algorithm_cli, algorithm_from_file
        ));
    }
    logger.verbose(&format!("Визначено алгоритм з файлу: '{}'", algorithm_from_file)); // [cite: 212]
    let algorithm_to_use = algorithm_from_file; // [cite: 212]

    let fek: SecretBytes; // [cite: 213]
    match key_management_flag { // [cite: 214]
        KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE => { // [cite: 214]
            logger.verbose("Файл вказує на використання ключа з файлу (-k). Спроба читання...");
            if let Some(key_file_path_arg) = &cli_args.key_file { // [cite: 215]
                let expected_key_len = match algorithm_to_use {
                     "aes-128" => 16, "aes-256" | "chacha20" => 32, //
                    _ => return Err(CryptoError::UnknownAlgorithm(algorithm_to_use.to_string())), // [cite: 216]
                };
                
                // Нова логіка: спробувати як відкритий, потім як захищений паролем
                match read_key_from_file(key_file_path_arg, expected_key_len, logger) { // [cite: 217]
                    Ok(plain_fek) => {
                        logger.verbose(&format!("Ключ з файлу '{}' успішно прочитано як відкритий/hex (для великого файлу).", key_file_path_arg));
                        fek = plain_fek;
                    }
                    Err(e_plain) => {
                        logger.verbose(&format!("Не вдалося прочитати ключ з '{}' як відкритий/hex (Помилка: {}) (для великого файлу). Спроба прочитати як зашифрований паролем файл ключа.", key_file_path_arg, e_plain));
                        match read_and_decrypt_password_protected_key_file(key_file_path_arg, logger) { //
                            Ok(decrypted_fek) => {
                                if decrypted_fek.expose_secret().len() != expected_key_len {
                                    logger.error(&format!(
                                        "Довжина ключа ({}), дешифрованого з файлу '{}' (для великого файлу), не відповідає очікуваній ({}) для алгоритму '{}'.",
                                        decrypted_fek.expose_secret().len(), key_file_path_arg, expected_key_len, algorithm_to_use
                                    ));
                                    return Err(CryptoError::InvalidKeyLength(decrypted_fek.expose_secret().len(), expected_key_len));
                                }
                                logger.verbose(&format!("Ключ успішно дешифровано з файлу '{}' за допомогою пароля (для великого файлу).", key_file_path_arg));
                                fek = decrypted_fek;
                            }
                            Err(e_encrypted) => {
                                logger.error(&format!("Не вдалося прочитати ключ з файлу '{}' ані як відкритий (Помилка: {}), ані як зашифрований паролем (Помилка: {}) (для великого файлу).", key_file_path_arg, e_plain, e_encrypted));
                                return Err(CryptoError::InvalidData(format!("Не вдалося обробити файл ключа '{}' (для великого файлу). Перевірте формат файлу або пароль.", key_file_path_arg)));
                            }
                        }
                    }
                }
            } else {
                return Err(CryptoError::InvalidData("Файл зашифровано з використанням файлу ключа (-k), але шлях не надано.".to_string())); //
            }
        }
        KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE => { // [cite: 218]
            logger.verbose("Ключ зашифровано паролем і зберігається в основному файлі."); // [cite: 218]
            if !cli_args.use_password && cli_args.key_file.is_some() { // [cite: 219]
                 logger.error("Файл вказує на використання пароля, але надано ключ-файл (-k) замість прапорця -p (або відсутності прапорців).");
                 return Err(CryptoError::InvalidData("Невідповідність: файл очікує пароль, а надано ключ-файл.".to_string())); // [cite: 220]
            }
            
            let mut salt = [0u8; PBKDF2_SALT_LEN]; //
            encrypted_file.read_exact(&mut salt)?; // [cite: 221]
            logger.verbose("Сіль прочитано з основного файлу."); // [cite: 221]

            let mut len_bytes_enc_fek = [0u8; 4]; // [cite: 221]
            encrypted_file.read_exact(&mut len_bytes_enc_fek)?; // [cite: 221]
            let enc_fek_len = u32::from_le_bytes(len_bytes_enc_fek) as usize; // [cite: 222]

            let mut encrypted_fek_from_main = vec![0u8; enc_fek_len]; // [cite: 222]
            encrypted_file.read_exact(&mut encrypted_fek_from_main)?; // [cite: 222]
            logger.verbose("Зашифрований FEK прочитано з основного файлу."); // [cite: 222]
            logger.info("Введіть пароль для дешифрування ключа:"); // [cite: 223]
            let password = read_password_securely(logger)?; // [cite: 223]
            println!(); // [cite: 223]
            let derived_key = derive_key_from_password(&password, &salt)?; // [cite: 223]
            
            let decrypted_bytes = decrypt_with_derived_key(&encrypted_fek_from_main, &derived_key)?; // [cite: 223]
            fek = SecretBytes::new(decrypted_bytes); // [cite: 224]
        }
        KEY_MANAGEMENT_FLAG_ENCRYPTED_KEY_FILE => { // [cite: 224]
            logger.verbose("Ключ зберігається в окремому файлі, який зашифровано паролем."); // [cite: 224]
            if let Some(key_file_path_arg) = &cli_args.key_file { // [cite: 225]
                // Додано перевірку довжини ключа тут
                let decrypted_fek_candidate = read_and_decrypt_password_protected_key_file(key_file_path_arg, logger)?; // [cite: 225]
                let expected_key_len = match algorithm_to_use {
                     "aes-128" => 16, "aes-256" | "chacha20" => 32,
                    _ => return Err(CryptoError::UnknownAlgorithm(algorithm_to_use.to_string())),
                };
                if decrypted_fek_candidate.expose_secret().len() != expected_key_len {
                    logger.error(&format!(
                        "Довжина ключа ({}), дешифрованого з файлу ключа '{}' (тип ENCRYPTED_KEY_FILE, великий файл), не відповідає очікуваній ({}) для алгоритму '{}'.",
                        decrypted_fek_candidate.expose_secret().len(), key_file_path_arg, expected_key_len, algorithm_to_use
                    ));
                    return Err(CryptoError::InvalidKeyLength(decrypted_fek_candidate.expose_secret().len(), expected_key_len));
                }
                fek = decrypted_fek_candidate;
            } else {
                 return Err(CryptoError::InvalidData("Файл зашифровано з використанням зашифрованого файлу ключа (-k), але шлях не надано.".to_string())); //
            }
        }
        _ => {
            return Err(CryptoError::InvalidData(format!("Невідомий прапор управління ключем у файлі: {}", key_management_flag))); //
        }
    }
    
    let expected_fek_len = match algorithm_to_use { // [cite: 228]
        "aes-128" => 16, "aes-256" | "chacha20" => 32, //
        _ => unreachable!(), // [cite: 229]
    };
    if fek.expose_secret().len() != expected_fek_len { // [cite: 230]
        return Err(CryptoError::InvalidKeyLength(fek.expose_secret().len(), expected_fek_len)); // [cite: 230]
    }
    logger.verbose("FEK успішно отримано та перевірено на довжину."); // [cite: 231]

    let mut output_file = File::create(&output_file_path).map_err(|e| { // [cite: 232]
        logger.error(&format!("Помилка створення вихідного файлу '{}': {}", output_file_path, e));
        CryptoError::IoError(e)
    })?;
    let mut hash_context = digest::Context::new(&digest::SHA256); // [cite: 233]
    let mut total_bytes_processed: u64 = 0; // [cite: 233]
    let mut buffer_for_block_payload = Vec::new(); // [cite: 233]

    while total_bytes_processed < original_file_size { // [cite: 234]
        let mut block_payload_len_bytes = [0u8; 4]; //
        match encrypted_file.read_exact(&mut block_payload_len_bytes) { // [cite: 235]
            Ok(_) => {}, // [cite: 235]
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && total_bytes_processed == original_file_size => { // [cite: 235]
                break; // [cite: 236]
            },
            Err(e) => { // [cite: 236]
                logger.error(&format!("Помилка читання розміру блоку шифртексту: {}", e));
                return Err(CryptoError::IoError(e)); // [cite: 237]
            }
        }
        let block_payload_len = u32::from_le_bytes(block_payload_len_bytes) as usize; // [cite: 237]
        let mut nonce = [0u8; 12]; // [cite: 238]
        encrypted_file.read_exact(&mut nonce)?; // [cite: 238]
        
        buffer_for_block_payload.resize(block_payload_len, 0); // [cite: 238]
        encrypted_file.read_exact(&mut buffer_for_block_payload)?; // [cite: 238]
        let unbound_key = match algorithm_to_use { // [cite: 239]
            "aes-128" => aead::UnboundKey::new(&aead::AES_128_GCM, fek.expose_secret()),
            "aes-256" => aead::UnboundKey::new(&aead::AES_256_GCM, fek.expose_secret()),
            "chacha20" => aead::UnboundKey::new(&aead::CHACHA20_POLY1305, fek.expose_secret()),
            _ => unreachable!(),
        }.map_err(|_| CryptoError::InvalidData(format!("Помилка створення ключа для {} при дешифруванні блоку", algorithm_to_use)))?;
        let less_safe_key = aead::LessSafeKey::new(unbound_key); // [cite: 240]
        let mut in_out = buffer_for_block_payload.clone(); // [cite: 240]

        let decrypted_block = less_safe_key.open_in_place( // [cite: 240]
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut in_out,
        ).map_err(|_| CryptoError::DecryptionError)?; //
        
        let bytes_to_write_this_block = std::cmp::min(decrypted_block.len(), (original_file_size - total_bytes_processed) as usize); // [cite: 241]
        hash_context.update(&decrypted_block[..bytes_to_write_this_block]); // [cite: 242]
        output_file.write_all(&decrypted_block[..bytes_to_write_this_block]).map_err(|e| { // [cite: 242]
            logger.error(&format!("Помилка запису дешифрованих даних: {}", e));
            CryptoError::IoError(e)
        })?;
        total_bytes_processed += bytes_to_write_this_block as u64; // [cite: 243]

        if total_bytes_processed % (100 * 1024 * 1024) < BLOCK_SIZE as u64 || total_bytes_processed == original_file_size { //
            let progress = (total_bytes_processed as f64 / original_file_size as f64) * 100.0; // [cite: 244]
            logger.info(&format!("Прогрес: {:.2}% ({}/{} байт)", progress, total_bytes_processed, original_file_size)); // [cite: 245]
        }
    }

    if total_bytes_processed != original_file_size { // [cite: 245]
        logger.error(&format!("Розмір оброблених даних ({}) не збігається з оригінальним розміром файлу ({}). Можливе пошкодження.", total_bytes_processed, original_file_size));
        return Err(CryptoError::InvalidData("Розмір дешифрованих даних не відповідає очікуваному.".to_string())); // [cite: 246]
    }
    
    let mut expected_final_hash_bytes = [0u8; 32]; //
    match encrypted_file.read_exact(&mut expected_final_hash_bytes) { // [cite: 247]
        Ok(_) => {},
        Err(e) => {
            logger.error(&format!("Помилка читання фінального хешу з файлу: {}", e));
            return Err(CryptoError::IoError(e)); // [cite: 248]
        }
    }

    let calculated_hash = hash_context.finish(); // [cite: 248]
    if calculated_hash.as_ref() != expected_final_hash_bytes { // [cite: 249]
        logger.error("Хеш дешифрованого вмісту великого файлу не відповідає оригінальному. Файл може бути пошкоджений або модифікований");
        return Err(CryptoError::IntegrityCheckFailed); // [cite: 250]
    }
    
    logger.info(&format!("Файл успішно дешифровано та збережено як '{}'", output_file_path)); // [cite: 250]
    logger.verbose("Цілісність великого файлу підтверджено перевіркою хешу"); // [cite: 251]
    Ok(())
}





/// Функція для перевірки та обробки великого файлу
pub(crate) fn process_large_file(
    file_path: &str,
    encrypt: bool,
    algorithm: &str,
    output_path: &Option<String>,
    logger: &Logger,
    cli_args: &Cli,
) -> Result<(), CryptoError> {
    // Перевіряємо, чи файл великий
    if !is_large_file(file_path, logger)? {
        logger.verbose(&format!("Файл '{}' не є великим файлом, буде оброблено стандартним способом", file_path));
        return Err(CryptoError::NotLargeFile);
    }
    
    logger.verbose(&format!("Виявлено великий файл '{}' (більше {}MB)", file_path, LARGE_FILE_THRESHOLD / (1024 * 1024)));
    
    // Викликаємо відповідну функцію обробки
    if encrypt {
        encrypt_large_file(file_path, algorithm, output_path, logger, cli_args)
    } else {
        decrypt_large_file(file_path, algorithm, output_path, logger, cli_args)
    }
}


fn main() -> Result<(), CryptoError> {
    let cli = Cli::parse();
    let logger = Logger::new(cli.silent, cli.verbose);
    logger.verbose(&format!("Отримані аргументи: {:?}", cli));

    match cli.action.as_str() {
        "encrypt" | "decrypt" => {
            // Перевірка, чи надано file_path або dir_path для encrypt/decrypt
            if cli.file_path.is_none() && cli.dir_path.is_none() {
                logger.error("Для дій 'encrypt' або 'decrypt' необхідно вказати шлях до файлу (-f) або каталогу (-d).");
                // Можна вивести допомогу clap тут, якщо потрібно
                // use clap::CommandFactory;
                // Cli::command().print_help().unwrap_or_default();
                return Err(CryptoError::InvalidData("Не вказано ціль для шифрування/дешифрування.".to_string()));
            }

            let action_is_encrypt = cli.action == "encrypt";

            if let Some(f_path_str) = &cli.file_path {
                logger.verbose(&format!("Ціль: Окремий файл '{}'", f_path_str));
                let metadata = std::fs::metadata(f_path_str).map_err(|e| {
                    logger.error(&format!("Не вдалося отримати метадані для файлу '{}': {}", f_path_str, e));
                    CryptoError::IoError(e)
                })?;
                if !metadata.is_file() {
                    logger.error(&format!("Вказаний шлях '{}' не є файлом.", f_path_str));
                    return Err(CryptoError::InvalidData(format!("'{}' не є файлом.", f_path_str)));
                }

                if action_is_encrypt {
                    if is_large_file(f_path_str, &logger)? { //
                        process_large_file(f_path_str, true, &cli.algorithm, &cli.output, &logger, &cli)?; // [cite: 261]
                    } else {
                        encrypt_file(f_path_str, &cli.algorithm, &cli.output, &logger, &cli)?; // [cite: 262]
                    }
                } else { // Decrypt
                    if peek_if_large_encrypted_format(f_path_str, &logger)? { // [cite: 263]
                        process_large_file(f_path_str, false, &cli.algorithm, &cli.output, &logger, &cli)?; // [cite: 264]
                    } else {
                        decrypt_file(f_path_str, &cli.algorithm, &cli.output, &logger, &cli)?; // [cite: 265]
                    }
                }
            } else if let Some(d_path_str) = &cli.dir_path {
                logger.verbose(&format!("Ціль: Каталог '{}'", d_path_str));
                let metadata = std::fs::metadata(d_path_str).map_err(|e| {
                    logger.error(&format!("Не вдалося отримати метадані для каталогу '{}': {}", d_path_str, e));
                    CryptoError::IoError(e)
                })?;
                if !metadata.is_dir() {
                    logger.error(&format!("Вказаний шлях '{}' не є каталогом.", d_path_str));
                    return Err(CryptoError::InvalidData(format!("'{}' не є каталогом.", d_path_str)));
                }

                if action_is_encrypt {
                    encrypt_directory(d_path_str, &cli.algorithm, &cli.output, &logger, &cli)?; // [cite: 269]
                } else {
                    decrypt_directory(d_path_str, &cli.output, &logger, &cli)?; // [cite: 270]
                }
            }
        }
        "steg-hide" => {
            if cli.dir_path.is_some() {
                logger.error("Дія 'steg-hide' не підтримується для каталогів. Використовуйте -f для секретного файлу.");
                return Err(CryptoError::InvalidData("Дія 'steg-hide' тільки для файлів.".to_string())); // [cite: 272]
            }
             if cli.file_path.is_none() { // Додаткова перевірка, оскільки required_if_eq може бути недостатньо без глобальної вимоги
                logger.error("Для 'steg-hide' не вказано секретний файл (-f).");
                return Err(CryptoError::InvalidData("Для 'steg-hide' не вказано секретний файл (-f).".to_string()));
            }
            handle_steg_hide(&cli, &logger)?; // [cite: 273]
        }
        "steg-extract" => {
            if cli.dir_path.is_some() {
                logger.error("Дія 'steg-extract' не підтримується для каталогів. Використовуйте -f для стего-зображення.");
                return Err(CryptoError::InvalidData("Дія 'steg-extract' тільки для файлів.".to_string())); // [cite: 274]
            }
            if cli.file_path.is_none() { // Додаткова перевірка
                logger.error("Для 'steg-extract' не вказано стего-зображення (-f).");
                return Err(CryptoError::InvalidData("Для 'steg-extract' не вказано стего-зображення (-f).".to_string()));
            }
             if cli.output.is_none() { // steg-extract вимагає -o
                logger.error("Для 'steg-extract' не вказано шлях для збереження вихідного файлу (-o).");
                return Err(CryptoError::InvalidData("Для 'steg-extract' не вказано шлях для збереження вихідного файлу (-o).".to_string()));
            }
            handle_steg_extract(&cli, &logger)?; // [cite: 275]
        }
        "gen-key" => { // Нова дія
            // Для gen-key file_path та dir_path не використовуються,
            // тому додаткових перевірок на них тут не потрібно.
            // Алгоритм (-l) використовується (має default).
            // Шлях виводу (-o) та пароль (-p) обробляються в handle_generate_key.
            handle_generate_key(&cli, &logger)?;
        }
        _ => {
            logger.error("Невідома дія. Доступні дії: 'encrypt', 'decrypt', 'steg-hide', 'steg-extract', 'gen-key'.");
            // use clap::CommandFactory;
            // Cli::command().print_help().unwrap_or_default();
            return Err(CryptoError::InvalidData("Невідома дія.".to_string())); // [cite: 276]
        }
    }
    Ok(())
}


fn peek_if_large_encrypted_format(file_path: &str, logger: &Logger) -> Result<bool, CryptoError> { 
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            logger.verbose(&format!("[Peek] Не вдалося відкрити файл '{}': {}. Не є великим зашифрованим файлом.", file_path, e));
            return Ok(false); // Якщо не можемо відкрити, то це не наш формат (або не помилка для peek)
        }
    };
    // Алгоритм (1) + KeyMgmtFlag (1) + LargeFileFlag (1)
    let mut header_prefix = [0u8; 3]; 
    if let Err(e) = file.read_exact(&mut header_prefix) {
        // Файл занадто малий або інша помилка читання
        if e.kind() != std::io::ErrorKind::UnexpectedEof { // Не логуємо EOF як помилку для peek, це очікувано для малих файлів
            logger.verbose(&format!("[Peek] Не вдалося прочитати заголовок з файлу '{}': {}. Не є великим зашифрованим.", file_path, e));
        }
        return Ok(false); 
    }
    // Перевіряємо третій байт (LargeFileFlag з моєї попередньої пропозиції)
    // ВАЖЛИВО: у моїй пропозиції для encrypt_large_file, LargeFileFlag (2u8) йде ТРЕТІМ байтом:
    // 1. algorithm_code, 2. key_management_flag, 3. large_file_flag (2u8)
    // Отже, ми перевіряємо header_prefix[2]
    Ok(header_prefix[2] == 2u8) 
}


fn encrypt_directory(
    input_dir_path_str: &str,
    algorithm_cli: &str, // Алгоритм з Cli
    output_dir_arg: &Option<String>,
    logger: &Logger,
    cli_args: &Cli, // Оригінальні cli_args для setup_encryption_key_material_once
) -> Result<(), CryptoError> {
    let input_dir_path = Path::new(input_dir_path_str);
    let base_output_dir_path = match output_dir_arg {
        Some(path) => PathBuf::from(path),
        None => {
            let dir_name = input_dir_path.file_name().ok_or_else(|| 
                CryptoError::InvalidData(format!("Не вдалося отримати ім'я каталогу з '{}'", input_dir_path_str))
            )?;
            let parent = input_dir_path.parent().unwrap_or_else(|| Path::new(""));
            parent.join(format!("{}_encrypted", dir_name.to_string_lossy()))
        }
    };
    logger.info(&format!("[Каталог] Шифрування '{}' -> '{}'", input_dir_path_str, base_output_dir_path.display()));

    // === ОДНОРАЗОВЕ НАЛАШТУВАННЯ КЛЮЧА для всього каталогу ===
    let common_key_material = setup_encryption_key_material_once(cli_args, algorithm_cli, logger)?;
    
    logger.verbose(&format!("[Каталог] Матеріали ключа для каталогу успішно підготовлено."));
    logger.verbose(&format!("[Каталог] Деталі: Algo: {}, Flag: {}, FEK (перші 4б): {:?}, SaltH: {}, EncFEKH (довжина): {:?}", 
        common_key_material.algorithm_name, 
        common_key_material.key_management_flag,
        common_key_material.fek.expose_secret().get(..4.min(common_key_material.fek.expose_secret().len())),
        common_key_material.salt_for_header.is_some(),
        common_key_material.encrypted_fek_for_header.as_ref().map(|v| v.len())
    ));

    for entry_result in WalkDir::new(input_dir_path) {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                logger.error(&format!("[Каталог] Помилка доступу до запису: {}. Пропускається.", e));
                continue;
            }
        };

        let current_input_path = entry.path();
        if current_input_path == input_dir_path {
            continue;
        }

        let relative_path = match current_input_path.strip_prefix(input_dir_path) {
            Ok(p) => p,
            Err(e) => {
                logger.error(&format!("[Каталог] Не вдалося отримати відносний шлях для {}: {}", current_input_path.display(), e));
                continue;
            }
        };
        
        let target_output_for_entry = base_output_dir_path.join(relative_path);

        if entry.file_type().is_dir() {
            if !target_output_for_entry.exists() {
                if let Err(e) = std::fs::create_dir_all(&target_output_for_entry) {
                    logger.error(&format!("[Каталог] Не вдалося створити підкаталог '{}': {}", target_output_for_entry.display(), e));
                } else {
                    logger.verbose(&format!("[Каталог] Створено підкаталог: {}", target_output_for_entry.display()));
                }
            }
        } else if entry.file_type().is_file() {
            let output_file_name = format!("{}.enc", current_input_path.file_name().unwrap_or_default().to_string_lossy());
            if let Some(parent_dir) = target_output_for_entry.parent() {
                 if !parent_dir.exists() {
                    std::fs::create_dir_all(parent_dir).map_err(CryptoError::IoError)?;
                 }
            }
            let final_output_file_path_str = target_output_for_entry.with_file_name(output_file_name).to_string_lossy().into_owned();
            let current_input_path_str = current_input_path.to_string_lossy().into_owned();
            
            let result = if is_large_file(&current_input_path_str, logger)? {
                 encrypt_large_file_for_directory( // ВИКЛИК НОВОЇ ФУНКЦІЇ
                    &current_input_path_str, 
                    &final_output_file_path_str, 
                    &common_key_material, // <--- Передаємо common_key_material
                    logger
                )
            } else {
                 encrypt_file_for_directory( // ВИКЛИК НОВОЇ ФУНКЦІЇ
                    &current_input_path_str, 
                    &final_output_file_path_str, 
                    &common_key_material, // <--- Передаємо common_key_material
                    logger
                )
            };

            if let Err(e) = result {
                 logger.error(&format!("[Каталог] Помилка шифрування файлу '{}': {:?}", current_input_path.display(), e));
            }
        }
    }
    logger.info("[Каталог] Шифрування завершено.");
    Ok(())
}


fn decrypt_directory(
    input_dir_path_str: &str,
    output_dir_arg: &Option<String>,
    logger: &Logger,
    cli_args: &Cli, // Оригінальні cli_args, які містять -k, -p тощо.
) -> Result<(), CryptoError> {
    let resolved_key_source_for_dir = setup_decryption_key_material_once(cli_args, &cli_args.algorithm, logger)?;
    let input_dir_path = Path::new(input_dir_path_str);
    let base_output_dir_path = match output_dir_arg {
        Some(path) => PathBuf::from(path),
        None => {
            let dir_name = input_dir_path.file_name().ok_or_else(||
                 CryptoError::InvalidData(format!("Не вдалося отримати ім'я каталогу з '{}'", input_dir_path_str))
            )?;
            let base_name = dir_name.to_string_lossy();
            let decrypted_name = if base_name.ends_with("_encrypted") {
                base_name.trim_end_matches("_encrypted").to_string()
            } else {
                format!("{}_decrypted", base_name)
            };
            let parent = input_dir_path.parent().unwrap_or_else(|| Path::new(""));
            parent.join(decrypted_name)
        }
    };
    logger.info(&format!("Дешифрування каталогу '{}' -> '{}'", input_dir_path_str, base_output_dir_path.display()));


    for entry_result in WalkDir::new(input_dir_path) {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                logger.error(&format!("Помилка доступу до запису в каталозі: {}", e));
                continue;
            }
        };

        let current_encrypted_path = entry.path(); // Поточний зашифрований файл
        if current_encrypted_path == input_dir_path { // Пропускаємо сам вхідний каталог
            continue;
        }

        let relative_path = match current_encrypted_path.strip_prefix(input_dir_path) {
            Ok(p) => p,
            Err(_) => {
                logger.error(&format!("Не вдалося отримати відносний шлях для {}", current_encrypted_path.display()));
                continue;
            }
        };
        
        let target_output_entry_path = base_output_dir_path.join(relative_path);

        if entry.file_type().is_dir() {
             if !target_output_entry_path.exists() { // Створюємо тільки якщо не існує
                if let Err(e) = std::fs::create_dir_all(&target_output_entry_path) {
                    logger.error(&format!("Не вдалося створити каталог '{}': {}", target_output_entry_path.display(), e));
                }
             }
        } else if entry.file_type().is_file() {
            if current_encrypted_path.extension().map_or(false, |ext| ext.to_ascii_lowercase() == "enc") {
                
                let original_file_name_str = current_encrypted_path.file_stem().map_or_else(
                    || "".to_string(), 
                    |stem| stem.to_string_lossy().into_owned()
                );
                
                if original_file_name_str.is_empty() && current_encrypted_path.file_name().map_or(false, |name| name.to_string_lossy().eq_ignore_ascii_case(".enc")) {
                    logger.verbose(&format!("[Каталог] Пропускається файл з іменем '.enc': {}", current_encrypted_path.display())); // Змінив на verbose
                    continue;
                }
                 if original_file_name_str.is_empty() {
                    logger.verbose(&format!("[Каталог] Пропускається файл з невірним іменем (без основи до .enc): {}", current_encrypted_path.display())); // Змінив на verbose
                    continue;
                }
                
                let final_output_file_path_str = target_output_entry_path.with_file_name(original_file_name_str).to_string_lossy().into_owned();
                let current_encrypted_file_path_str = current_encrypted_path.to_string_lossy().into_owned();

                logger.verbose(&format!("Обробка файлу для дешифрування: {}", current_encrypted_file_path_str));
                
                let mut per_file_cli_options = cli_args.clone();
                per_file_cli_options.output = Some(final_output_file_path_str.clone());
                let result = if peek_if_large_encrypted_format(&current_encrypted_file_path_str, logger)? {
                    decrypt_large_file_for_directory(
                         &current_encrypted_file_path_str,   // Аргумент для input_path_str_param
                        &final_output_file_path_str, // Аргумент для output_path_str_param
                        &resolved_key_source_for_dir,   // Аргумент для resolved_key_source_param
                        logger  
                        )
                } else {
                    decrypt_file_for_directory(
                         &current_encrypted_file_path_str,   // Аргумент для input_path_str_param
                        &final_output_file_path_str, // Аргумент для output_path_str_param
                        &resolved_key_source_for_dir,   // Аргумент для resolved_key_source_param
                        logger 
                        )
                };
                if let Err(e) = result {
                    logger.error(&format!("Помилка дешифрування файлу '{}': {:?}", current_encrypted_path.display(), e));
                }
            } else {
                logger.verbose(&format!("Пропускається файл без розширення .enc: {}", current_encrypted_path.display()));
            }
        }
    }
    logger.info("Дешифрування каталогу завершено.");
    Ok(())
}


#[derive(Clone)] 
struct EncryptionKeyMaterial {
    fek: SecretBytes,
    key_management_flag: u8,
    algorithm_name: String,
    salt_for_header: Option<[u8; PBKDF2_SALT_LEN]>, // Сіль, ЯКЩО key_management_flag це PASSWORD_IN_MAIN_FILE
    encrypted_fek_for_header: Option<Vec<u8>>,   // Зашифрований FEK, ЯКЩО key_management_flag це PASSWORD_IN_MAIN_FILE
}

#[derive(Clone)] // Для ResolvedDecryptionKey
enum ResolvedDecryptionKey {
    Fek(SecretBytes),
    UsePassword(SecretString),
}

fn setup_encryption_key_material_once(
    cli_args: &Cli, 
    algorithm_to_use: &str,
    logger: &Logger,
) -> Result<EncryptionKeyMaterial, CryptoError> {
    let fek: SecretBytes;
    let key_management_flag: u8; 
    let mut salt_for_header: Option<[u8; PBKDF2_SALT_LEN]> = None; // [cite: 335]
    let mut encrypted_fek_for_header: Option<Vec<u8>> = None; // [cite: 336]

    if let Some(key_file_path_arg) = &cli_args.key_file { // [cite: 338]
        logger.verbose(&format!("Спроба використання ключа з файлу '{}' для операції з каталогом", key_file_path_arg));
        let expected_key_len = match algorithm_to_use { // [cite: 339]
            "aes-128" => 16, // [cite: 339]
            "aes-256" | "chacha20" => 32, // [cite: 339, 340]
            _ => return Err(CryptoError::UnknownAlgorithm(algorithm_to_use.to_string())), // [cite: 340]
        };

        match read_key_from_file(key_file_path_arg, expected_key_len, logger) { // [cite: 341]
            Ok(plain_fek) => {
                logger.verbose(&format!("Ключ успішно прочитано з файлу '{}' (як відкритий/hex) для операції з каталогом.", key_file_path_arg));
                fek = plain_fek;
                key_management_flag = KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE; // [cite: 341]
                // Ігноруємо -S та -p, якщо надано -k для каталогу, як і раніше
                if cli_args.use_password {
                    logger.warn("Для каталогу: Прапорець -p (пароль) ігнорується, оскільки ключ з -k успішно прочитано як відкритий.");
                }
                if cli_args.save_key_path.is_some() {
                     logger.warn("Для каталогу: Прапорець -S (зберегти ключ) ігнорується, оскільки ключ надано через -k.");
                }
            }
            Err(e_plain) => {
                logger.verbose(&format!("Для каталогу: Не вдалося прочитати ключ з '{}' як відкритий/hex (Помилка: {}). Спроба прочитати як зашифрований паролем файл ключа.", key_file_path_arg, e_plain));
                match read_and_decrypt_password_protected_key_file(key_file_path_arg, logger) {
                    Ok(decrypted_fek) => {
                        if decrypted_fek.expose_secret().len() != expected_key_len {
                            logger.error(&format!(
                                "Для каталогу: Довжина ключа ({}), дешифрованого з файлу '{}', не відповідає очікуваній ({}) для алгоритму '{}'.",
                                decrypted_fek.expose_secret().len(), key_file_path_arg, expected_key_len, algorithm_to_use
                            ));
                            return Err(CryptoError::InvalidKeyLength(decrypted_fek.expose_secret().len(), expected_key_len));
                        }
                        logger.verbose(&format!("Для каталогу: Ключ успішно дешифровано з файлу '{}' за допомогою пароля.", key_file_path_arg));
                        fek = decrypted_fek;
                        key_management_flag = KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE; 
                        if cli_args.save_key_path.is_some() {
                             logger.warn("Для каталогу: Прапорець -S (зберегти ключ) ігнорується, оскільки ключ надано через -k (і успішно дешифровано).");
                        }
                    }
                    Err(e_encrypted) => {
                        logger.error(&format!("Для каталогу: Не вдалося прочитати ключ з файлу '{}' ані як відкритий (Помилка: {}), ані як зашифрований паролем (Помилка: {}).", key_file_path_arg, e_plain, e_encrypted));
                        return Err(CryptoError::InvalidData(format!("Для каталогу: Не вдалося обробити файл ключа '{}'. Перевірте формат файлу або пароль.", key_file_path_arg)));
                    }
                }
            }
        }
    } else {
        logger.verbose("Генерація нового ключа для операції з каталогом."); // [cite: 341]
        let generated_fek = generate_random_key(algorithm_to_use)?; // [cite: 342]

        if let Some(save_key_to_path_arg) = &cli_args.save_key_path { // [cite: 342]
            if cli_args.use_password { // [cite: 342]
                save_password_protected_key_file(&generated_fek, save_key_to_path_arg, logger)?;
                key_management_flag = KEY_MANAGEMENT_FLAG_ENCRYPTED_KEY_FILE; // [cite: 343]
            } else {
                save_key_to_file(&generated_fek, save_key_to_path_arg, logger)?;
                key_management_flag = KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE; // [cite: 344]
            }
        } else { 
            if cli_args.use_password { // [cite: 344]
                logger.verbose("Для каталогу: явно вказано використання пароля (-p).");
            } else {
                logger.verbose("Для каталогу (за замовчуванням): використовується захист паролем."); // [cite: 345]
            }
            logger.info("Введіть пароль ОДИН РАЗ для всього каталогу:"); // [cite: 346]
            let password = read_password_securely(logger)?; // [cite: 347]
            println!(); // [cite: 347]
            let salt = generate_random_bytes(); // [cite: 347]
            salt_for_header = Some(salt); // [cite: 347]
            let derived_key = derive_key_from_password(&password, &salt)?; // [cite: 348]
            encrypted_fek_for_header = Some(encrypt_with_derived_key(generated_fek.expose_secret(), &derived_key)?); // [cite: 349]
            key_management_flag = KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE; // [cite: 349]
        }
        fek = generated_fek; // [cite: 350]
    }

    Ok(EncryptionKeyMaterial { // [cite: 351]
        fek,
        key_management_flag,
        algorithm_name: algorithm_to_use.to_string(),
        salt_for_header,
        encrypted_fek_for_header,
    })
}

fn setup_decryption_key_material_once(
    cli_args: &Cli,
    algorithm_from_cli: &str, // Використовується для визначення expected_key_len при читанні файлу ключа
    logger: &Logger,
) -> Result<ResolvedDecryptionKey, CryptoError> {
    if let Some(key_file_path) = &cli_args.key_file {
        logger.verbose(&format!("[DecryptSetup] Використання файлу ключа: '{}'", key_file_path));
        let expected_key_len = match algorithm_from_cli {
            "aes-128" => 16,
            "aes-256" | "chacha20" => 32,
            _ => return Err(CryptoError::UnknownAlgorithm(format!(
                "Неможливо визначити очікувану довжину ключа для алгоритму '{}' при читанні файлу ключа.", 
                algorithm_from_cli
            ))),
        };

        // Спроба прочитати як простий (hex) ключ
        match read_key_from_file(key_file_path, expected_key_len, logger) {
            Ok(fek) => {
                logger.verbose("[DecryptSetup] Ключ з файлу успішно зчитано як простий (hex).");
                Ok(ResolvedDecryptionKey::Fek(fek))
            }
            Err(e_plain) => { 
                logger.verbose(&format!("[DecryptSetup] Не вдалося зчитати ключ як простий (помилка: {}), спроба як захищений паролем файл ключа.", e_plain));
                match read_and_decrypt_password_protected_key_file(key_file_path, logger) { // Ця функція сама запитає пароль
                    Ok(fek) => {
                         if fek.expose_secret().len() != expected_key_len {
                            logger.error(&format!("Довжина дешифрованого ключа з файлу ключа ({}) не відповідає очікуваній ({}) для алгоритму {}", 
                                fek.expose_secret().len(), expected_key_len, algorithm_from_cli));
                            return Err(CryptoError::InvalidKeyLength(fek.expose_secret().len(), expected_key_len));
                         }
                         Ok(ResolvedDecryptionKey::Fek(fek))
                    },
                    Err(e_encrypted) => {
                        logger.error(&format!("[DecryptSetup] Не вдалося зчитати файл ключа '{}' ані як простий, ані як захищений паролем. Помилка (простий): {}. Помилка (захищений): {}", key_file_path, e_plain, e_encrypted));
                        Err(CryptoError::InvalidData(format!("Не вдалося обробити файл ключа '{}'.", key_file_path))) // Повертаємо більш загальну помилку
                    }
                }
            }
        }
    } else if cli_args.use_password { // Явно вказано -p
        logger.verbose("[DecryptSetup] Використання пароля (-p) для дешифрування.");
        logger.info("Введіть пароль ОДИН РАЗ для цієї операції:");
        let password = read_password_securely(logger)?;
        println!();
        Ok(ResolvedDecryptionKey::UsePassword(password))
    } else { 
        // Немає -k і немає явного -p. Припускаємо, що файли можуть бути зашифровані паролем за замовчуванням.
        logger.verbose("[DecryptSetup] Ключ (-k) та пароль (-p) не вказані. Буде запитано пароль (за замовчуванням для файлів, що його потребують).");
        logger.info("Введіть пароль ОДИН РАЗ для цієї операції (якщо файли в каталозі його потребують):");
        let password = read_password_securely(logger)?;
        println!();
        Ok(ResolvedDecryptionKey::UsePassword(password))
    }
}


fn encrypt_file_for_directory(
    input_path_str: &str,
    output_path_str: &str, // Повний шлях до вихідного файлу
    key_material: &EncryptionKeyMaterial, // Готові матеріали ключа
    logger: &Logger,
) -> Result<(), CryptoError> {
    logger.info(&format!("Шифрування (для каталогу): '{}' -> '{}'", input_path_str, output_path_str));
    logger.verbose(&format!("  Використання алгоритму: '{}', Flag KM: {}", 
        key_material.algorithm_name, key_material.key_management_flag));

    let mut input_file_data = Vec::new();
    File::open(input_path_str)
        .map_err(|e| { logger.error(&format!("Не вдалося відкрити '{}': {}", input_path_str, e)); CryptoError::IoError(e) })?
        .read_to_end(&mut input_file_data)
        .map_err(|e| { logger.error(&format!("Не вдалося прочитати '{}': {}", input_path_str, e)); CryptoError::IoError(e) })?;

    let hash = calculate_hash(&input_file_data);
    
    let encrypted_data_payload = encrypt_data(
        &input_file_data,
        key_material.fek.expose_secret(), // Використовуємо FEK з key_material
        &key_material.algorithm_name,    // Використовуємо алгоритм з key_material
        input_file_data.len(),
        &hash
    )?;

    let mut output_file = File::create(output_path_str)
        .map_err(|e| { logger.error(&format!("Не вдалося створити '{}': {}", output_path_str, e)); CryptoError::IoError(e) })?;

    // Запис заголовка на основі key_material
    let algorithm_code = match key_material.algorithm_name.as_str() {
        "aes-128" => 0x01u8, 
        "aes-256" => 0x02u8, 
        "chacha20" => 0x03u8,
        _ => return Err(CryptoError::UnknownAlgorithm(key_material.algorithm_name.clone())),
    };
    output_file.write_all(&[algorithm_code])?;
    output_file.write_all(&[key_material.key_management_flag])?; // Цей прапор однаковий для всіх файлів каталогу

    // Якщо каталог шифрується паролем, то кожен файл отримує однакову сіль та зашифрований FEK
    if key_material.key_management_flag == KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE {
        if let Some(salt) = &key_material.salt_for_header {
            output_file.write_all(salt)?;
        } else {
            // Ця помилка не мала б статися, якщо setup_encryption_key_material_once працює правильно
            return Err(CryptoError::InvalidData("[DirEncrypt] Сіль для заголовка відсутня, коли очікувалася.".to_string()));
        }
        if let Some(enc_fek) = &key_material.encrypted_fek_for_header {
            let len_bytes = (enc_fek.len() as u32).to_le_bytes();
            output_file.write_all(&len_bytes)?;
            output_file.write_all(enc_fek)?;
        } else {
             return Err(CryptoError::InvalidData("[DirEncrypt] Зашифрований FEK для заголовка відсутній, коли очікувався.".to_string()));
        }
    }
    // Якщо key_management_flag це PLAIN_KEY_FILE або ENCRYPTED_KEY_FILE, то сіль/зашифрований FEK не пишуться сюди.
    // Вони стосуються окремого файлу ключа.
    
    output_file.write_all(&encrypted_data_payload)?;
    logger.info(&format!("Файл '{}' успішно зашифровано.", output_path_str)); // Можливо, це повідомлення краще зробити verbose
    Ok(())
}


fn encrypt_large_file_for_directory(
    input_path_str: &str,
    output_path_str: &str, // Повний шлях
    key_material: &EncryptionKeyMaterial,
    logger: &Logger,
    // block_size: usize, // Можна передавати або брати з константи
) -> Result<(), CryptoError> {
    logger.info(&format!("Шифрування великого файлу (для каталогу): '{}' -> '{}'", input_path_str, output_path_str));
    logger.verbose(&format!("  Використання алгоритму: '{}', Flag KM: {}", 
        key_material.algorithm_name, key_material.key_management_flag));

    let mut input_file = File::open(input_path_str)?; 
    let file_size = input_file.metadata()?.len();
    let mut output_file = File::create(output_path_str)?; 

    // Запис заголовка на основі key_material
    let algorithm_code = match key_material.algorithm_name.as_str() {
        "aes-128" => 0x01u8, "aes-256" => 0x02u8, "chacha20" => 0x03u8,
        _ => return Err(CryptoError::UnknownAlgorithm(key_material.algorithm_name.clone())),
    };
    output_file.write_all(&[algorithm_code])?;
    output_file.write_all(&[key_material.key_management_flag])?;
    output_file.write_all(&[2u8])?; // Прапор великого файлу
    output_file.write_all(&(file_size as u64).to_le_bytes())?;

    if key_material.key_management_flag == KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE {
        if let Some(salt) = &key_material.salt_for_header {
            output_file.write_all(salt)?;
        } // обробка помилки
        if let Some(enc_fek) = &key_material.encrypted_fek_for_header {
            let len_bytes = (enc_fek.len() as u32).to_le_bytes();
            output_file.write_all(&len_bytes)?;
            output_file.write_all(enc_fek)?;
        } // обробка помилки
    }
    
    let mut buffer = vec![0u8; BLOCK_SIZE]; // BLOCK_SIZE - константа
    let mut remaining_bytes = file_size;
    let mut total_bytes_processed: u64 = 0;
    let mut hash_context = digest::Context::new(&digest::SHA256);

    while remaining_bytes > 0 {
        let current_block_size = std::cmp::min(BLOCK_SIZE as u64, remaining_bytes) as usize;
        input_file.read_exact(&mut buffer[..current_block_size])?;
        hash_context.update(&buffer[..current_block_size]);

        let nonce = generate_random_nonce();
        let unbound_key = match key_material.algorithm_name.as_str() { // Використовуємо з key_material
            "aes-128" => aead::UnboundKey::new(&aead::AES_128_GCM, key_material.fek.expose_secret()),
            "aes-256" => aead::UnboundKey::new(&aead::AES_256_GCM, key_material.fek.expose_secret()),
            "chacha20" => aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key_material.fek.expose_secret()),
            _ => return Err(CryptoError::UnknownAlgorithm(key_material.algorithm_name.clone())),
        }.map_err(|_| CryptoError::InvalidData(format!("Помилка створення ключа для {} (великий файл, каталог)", key_material.algorithm_name)))?;
        
        let less_safe_key = aead::LessSafeKey::new(unbound_key);
        let mut in_out_block = buffer[..current_block_size].to_vec();
        
        less_safe_key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce), 
            aead::Aad::empty(), 
            &mut in_out_block
        ).map_err(|_e| CryptoError::InvalidData("Помилка шифрування блоку (великий файл, каталог)".to_string()))?; 
        
        let encrypted_block_len = (in_out_block.len() as u32).to_le_bytes();
        output_file.write_all(&encrypted_block_len)?;
        output_file.write_all(&nonce)?;
        output_file.write_all(&in_out_block)?;
        
        remaining_bytes -= current_block_size as u64;
        total_bytes_processed += current_block_size as u64;
        // логування прогресу
        if total_bytes_processed % (100 * 1024 * 1024) < BLOCK_SIZE as u64 || remaining_bytes == 0 {
             let progress = (total_bytes_processed as f64 / file_size as f64) * 100.0;
             logger.info(&format!("Прогрес (файл {}): {:.2}%", input_path_str, progress.min(100.0)));
        }
    }
    let final_hash = hash_context.finish();
    output_file.write_all(final_hash.as_ref())?;
    // ... (кінець циклу)
    
    logger.info(&format!("Великий файл '{}' успішно зашифровано.", output_path_str));
    Ok(())
}



fn decrypt_file_for_directory(
    input_path_str: &str,
    output_path_str: &str, // Повний шлях до вихідного файлу
    resolved_key_source: &ResolvedDecryptionKey, // Готовий ключ або пароль
    logger: &Logger,
) -> Result<(), CryptoError> {
    logger.info(&format!("Дешифрування (для каталогу): '{}' -> '{}'", input_path_str, output_path_str));

    let mut encrypted_file = File::open(input_path_str)
        .map_err(|e| { logger.error(&format!("Не вдалося відкрити '{}': {}", input_path_str, e)); CryptoError::IoError(e) })?;
    
    // --- Читання заголовка файлу ---
    let mut algorithm_code_buffer = [0u8; 1];
    encrypted_file.read_exact(&mut algorithm_code_buffer)?;
    let algorithm_from_file_code = algorithm_code_buffer[0];

    let mut key_management_flag_buffer = [0u8; 1];
    encrypted_file.read_exact(&mut key_management_flag_buffer)?;
    let key_management_flag_from_file = key_management_flag_buffer[0];

    let algorithm_to_use = match algorithm_from_file_code {
        0x01 => "aes-128", 0x02 => "aes-256", 0x03 => "chacha20",
        _ => return Err(CryptoError::UnknownAlgorithm(format!("0x{:02x} з файлу {}", algorithm_from_file_code, input_path_str))),
    };
    logger.verbose(&format!("  Алгоритм з файлу: '{}', Flag KM: {}", algorithm_to_use, key_management_flag_from_file));

    // --- ОТРИМАННЯ ФІНАЛЬНОГО FEK ---
    let fek: SecretBytes = match resolved_key_source {
        ResolvedDecryptionKey::Fek(the_fek) => {
            logger.verbose("  Використання наданого FEK.");
            if key_management_flag_from_file != KEY_MANAGEMENT_FLAG_PLAIN_KEY_FILE &&
               key_management_flag_from_file != KEY_MANAGEMENT_FLAG_ENCRYPTED_KEY_FILE {
                logger.warn(&format!("  Невідповідність: надано прямий ключ, але прапор файлу ({}) не PLAIN або ENCRYPTED_KEY_FILE.", key_management_flag_from_file));
            }
            the_fek.clone() // Потрібен Clone для SecretBytes
        }
        ResolvedDecryptionKey::UsePassword(password_str) => {
            if key_management_flag_from_file == KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE {
                logger.verbose("  Використання наданого пароля для отримання FEK з заголовка файлу.");
                let mut salt_from_file = [0u8; PBKDF2_SALT_LEN]; 
                encrypted_file.read_exact(&mut salt_from_file)?;
                
                let mut len_bytes = [0u8; 4]; encrypted_file.read_exact(&mut len_bytes)?;
                let enc_fek_len = u32::from_le_bytes(len_bytes) as usize;
                let mut encrypted_fek_from_this_file = vec![0u8; enc_fek_len];
                encrypted_file.read_exact(&mut encrypted_fek_from_this_file)?;

                let derived_key = derive_key_from_password(password_str, &salt_from_file)?;
                SecretBytes::new(decrypt_with_derived_key(&encrypted_fek_from_this_file, &derived_key)?)
            } else {
                logger.error(&format!("  Надано пароль, але прапор файлу ({}) не PASSWORD_IN_MAIN_FILE. Файл: {}", key_management_flag_from_file, input_path_str));
                return Err(CryptoError::InvalidData("Невідповідність методу ключа: очікувався пароль, але формат файлу інший.".to_string()));
            }
        }
    };
    
    // Перевірка довжини отриманого FEK
    let expected_fek_len = match algorithm_to_use {
        "aes-128" => 16, "aes-256" | "chacha20" => 32,
        _ => return Err(CryptoError::UnknownAlgorithm(algorithm_to_use.to_string())),
    };
    if fek.expose_secret().len() != expected_fek_len {
        return Err(CryptoError::InvalidKeyLength(fek.expose_secret().len(), expected_fek_len));
    }

    // Читання решти даних (encrypted_data_payload)
    let mut encrypted_data_payload = Vec::new();
    encrypted_file.read_to_end(&mut encrypted_data_payload)?;
    
    let decrypted_with_original_metadata = decrypt_data(
        &encrypted_data_payload,
        fek.expose_secret(),
        algorithm_to_use,
        logger 
    )?;
    
    let (original_size, expected_hash, decrypted_data_content) = extract_metadata_with_hash(&decrypted_with_original_metadata)?;
    if !validate_hash(decrypted_data_content, &expected_hash) {
        return Err(CryptoError::HashMismatch);
    }
    let final_decrypted_data = &decrypted_data_content[..original_size];
   // Створюємо батьківський каталог для вихідного файлу, якщо він не існує
    if let Some(parent_dir) = Path::new(output_path_str).parent() {
        if !parent_dir.exists() {
            std::fs::create_dir_all(parent_dir).map_err(|e| {
                logger.error(&format!("Не вдалося створити батьківський каталог '{}' для файлу '{}': {}", parent_dir.display(), output_path_str, e));
                CryptoError::IoError(e)
        })?;
    }
}
    let mut output_decrypted_file = File::create(output_path_str)?;
    output_decrypted_file.write_all(final_decrypted_data)?;

    logger.info(&format!("Файл '{}' успішно дешифровано.", output_path_str)); // Можливо verbose
    Ok(())
}


fn decrypt_large_file_for_directory(
    input_path_str: &str,
    output_path_str: &str,
    resolved_key_source: &ResolvedDecryptionKey,
    logger: &Logger,
) -> Result<(), CryptoError> {
    logger.info(&format!("Дешифрування великого файлу (для каталогу): '{}' -> '{}'", input_path_str, output_path_str));

    let mut encrypted_file = File::open(input_path_str)?; // Додай .map_err
    
    // --- Читання заголовка великого файлу ---
    let mut algorithm_code_buffer = [0u8; 1]; encrypted_file.read_exact(&mut algorithm_code_buffer)?;
    let mut key_management_flag_buffer = [0u8; 1]; encrypted_file.read_exact(&mut key_management_flag_buffer)?;
    let mut large_file_flag_buffer = [0u8; 1]; encrypted_file.read_exact(&mut large_file_flag_buffer)?;
    if large_file_flag_buffer[0] != 2u8 { /* ... помилка ... */ return Err(CryptoError::InvalidData("Не великий файл".to_string())); }
    let mut size_bytes = [0u8; 8]; encrypted_file.read_exact(&mut size_bytes)?;
    let original_file_size = u64::from_le_bytes(size_bytes);
    
    let algorithm_from_file_code = algorithm_code_buffer[0];
    let key_management_flag_from_file = key_management_flag_buffer[0];
    let algorithm_to_use = match algorithm_from_file_code {
        0x01 => "aes-128", 0x02 => "aes-256", 0x03 => "chacha20",
        _ => return Err(CryptoError::UnknownAlgorithm(format!("0x{:02x}", algorithm_from_file_code))),
    };
    logger.verbose(&format!("  Алгоритм з файлу (великий): '{}', Flag KM: {}", algorithm_to_use, key_management_flag_from_file));

    // --- ОТРИМАННЯ ФІНАЛЬНОГО FEK (аналогічно до decrypt_file_for_directory) ---
    let fek: SecretBytes = match resolved_key_source {
        ResolvedDecryptionKey::Fek(the_fek) => {
            // ... (перевірка узгодженості з key_management_flag_from_file) ...
            logger.verbose("  Використання наданого FEK (великий файл).");
            the_fek.clone()
        }
        ResolvedDecryptionKey::UsePassword(password_str) => {
            if key_management_flag_from_file == KEY_MANAGEMENT_FLAG_PASSWORD_IN_MAIN_FILE {
                logger.verbose("  Використання наданого пароля для отримання FEK з заголовка (великий файл).");
                let mut salt_from_file = [0u8; PBKDF2_SALT_LEN]; encrypted_file.read_exact(&mut salt_from_file)?;
                let mut len_bytes = [0u8; 4]; encrypted_file.read_exact(&mut len_bytes)?;
                let enc_fek_len = u32::from_le_bytes(len_bytes) as usize;
                let mut encrypted_fek_from_this_file = vec![0u8; enc_fek_len];
                encrypted_file.read_exact(&mut encrypted_fek_from_this_file)?;
                
                let derived_key = derive_key_from_password(password_str, &salt_from_file)?;
                SecretBytes::new(decrypt_with_derived_key(&encrypted_fek_from_this_file, &derived_key)?)
            } else {
                // ... (помилка невідповідності) ...
                return Err(CryptoError::InvalidData("Невідповідність методу ключа для великого файлу (пароль).".to_string()));
            }
        }
    };
    // ... (перевірка довжини fek) ...
    let expected_fek_len = match algorithm_to_use {
    "aes-128" => 16,
    "aes-256" | "chacha20" => 32,
    _ => { // Ця гілка не мала б спрацювати, якщо algorithm_to_use валідний
        logger.error(&format!("Невідомий алгоритм '{}' при перевірці довжини ключа для великого файлу.", algorithm_to_use));
        return Err(CryptoError::UnknownAlgorithm(algorithm_to_use.to_string()));
    }
};
if fek.expose_secret().len() != expected_fek_len {
    logger.error(&format!(
        "Невідповідність довжини ключа для великого файлу. Алгоритм: {}, Очікувалося: {}, Отримано: {}.",
        algorithm_to_use, expected_fek_len, fek.expose_secret().len()
    ));
    return Err(CryptoError::InvalidKeyLength(fek.expose_secret().len(), expected_fek_len));
}
logger.verbose(&format!("FEK для великого файлу (алгоритм: {}) успішно перевірено на довжину ({} байт).", algorithm_to_use, expected_fek_len));
    // --- Тіло дешифрування блоками ---
    // Створюємо батьківський каталог для вихідного файлу, якщо він не існує
if let Some(parent_dir) = Path::new(output_path_str).parent() {
    if !parent_dir.exists() {
        std::fs::create_dir_all(parent_dir).map_err(|e| {
            logger.error(&format!("Не вдалося створити батьківський каталог '{}' для файлу '{}': {}", parent_dir.display(), output_path_str, e));
            CryptoError::IoError(e)
        })?;
    }
}
    let mut output_file = File::create(output_path_str)?; 
    let mut hash_context = digest::Context::new(&digest::SHA256);
    let mut total_bytes_processed: u64 = 0;
    let mut buffer_for_block_payload = Vec::new();

    while total_bytes_processed < original_file_size {
        let mut block_payload_len_bytes = [0u8; 4]; 
        if encrypted_file.read_exact(&mut block_payload_len_bytes).is_err() { 
            if total_bytes_processed == original_file_size { break; } // Нормальне завершення
            return Err(CryptoError::InvalidData("Не вдалося прочитати довжину блоку".to_string()));
        }
        let block_payload_len = u32::from_le_bytes(block_payload_len_bytes) as usize;

        let mut nonce = [0u8; 12]; encrypted_file.read_exact(&mut nonce)?;
        
        buffer_for_block_payload.resize(block_payload_len, 0); 
        encrypted_file.read_exact(&mut buffer_for_block_payload)?;

        let unbound_key = match algorithm_to_use {
            "aes-128" => aead::UnboundKey::new(&aead::AES_128_GCM, fek.expose_secret()),
            "aes-256" => aead::UnboundKey::new(&aead::AES_256_GCM, fek.expose_secret()),
            "chacha20" => aead::UnboundKey::new(&aead::CHACHA20_POLY1305, fek.expose_secret()),
            _ => return Err(CryptoError::UnknownAlgorithm(algorithm_to_use.to_string())),
        }.map_err(|_| CryptoError::InvalidData(format!("Помилка створення ключа для {} (великий файл, дешифр, каталог)", algorithm_to_use)))?;
        
        let less_safe_key = aead::LessSafeKey::new(unbound_key);
        let mut in_out_block = buffer_for_block_payload.clone();

        let decrypted_block = less_safe_key.open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut in_out_block,
        ).map_err(|_e| {
            logger.error(&format!("[decrypt_large_file_for_directory] Помилка дешифрування блоку даних для файлу {}. Можливо, неправильний ключ/пароль або дані пошкоджено.", input_path_str));
            CryptoError::DecryptionError
        })?;
        
        let bytes_to_write_this_block = std::cmp::min(decrypted_block.len(), (original_file_size - total_bytes_processed) as usize);
        hash_context.update(&decrypted_block[..bytes_to_write_this_block]);
        output_file.write_all(&decrypted_block[..bytes_to_write_this_block])?;
        
        total_bytes_processed += bytes_to_write_this_block as u64;
        // логування прогресу
        if total_bytes_processed % (100 * 1024 * 1024) < BLOCK_SIZE as u64 || total_bytes_processed == original_file_size {
            let progress = (total_bytes_processed as f64 / original_file_size as f64) * 100.0;
            logger.info(&format!("Прогрес (файл {}): {:.2}%", input_path_str, progress.min(100.0)));
        }
    }
    // ... (перевірка total_bytes_processed, читання та перевірка фінального хешу)
    if total_bytes_processed != original_file_size { return Err(CryptoError::InvalidData("Розмір не збігається".to_string()));}
    let mut expected_final_hash_bytes = [0u8; 32]; encrypted_file.read_exact(&mut expected_final_hash_bytes)?;
    let calculated_hash = hash_context.finish();
    if calculated_hash.as_ref() != expected_final_hash_bytes { return Err(CryptoError::IntegrityCheckFailed); }
    // ... (кінець циклу)
    
    logger.info(&format!("Великий файл '{}' успішно дешифровано.", output_path_str)); // Можливо verbose
    Ok(())
}




fn handle_steg_hide(cli: &Cli, logger: &Logger) -> Result<(), CryptoError> {
    let secret_file_path = cli.file_path.as_ref().ok_or_else(|| CryptoError::InvalidData("Для 'steg-hide' не вказано секретний файл (-f).".to_string()))?;
    let cover_image_input_path = cli.cover_image_path.as_ref().ok_or_else(|| CryptoError::InvalidData("Для 'steg-hide' не вказано зображення-контейнер (-c).".to_string()))?;
    let stego_image_output_path = cover_image_input_path; // Файл-контейнер буде змінено/перезаписано

    logger.info(&format!("[STEG HIDE] Завдання: сховати '{}' у '{}' (файл контейнера буде змінено)", secret_file_path, stego_image_output_path));

    // 1. Читаємо секретний файл
    let mut secret_content = Vec::new();
    File::open(secret_file_path)?.read_to_end(&mut secret_content)?;
    logger.verbose(&format!("Секретний файл '{}' прочитано: {} байт.", secret_file_path, secret_content.len()));


    let temp_encrypted_secret_path = format!("{}.temp_enc_for_steg", secret_file_path);

    encrypt_file(
        secret_file_path, 
        &cli.algorithm, 
        &Some(temp_encrypted_secret_path.clone()), // Зберігаємо у тимчасовий файл
        logger, 
        cli // Передаємо всі cli аргументи
    )?;
    logger.verbose("Секретний файл тимчасово зашифровано.");

    let mut encrypted_secret_payload_from_file = Vec::new();
    File::open(&temp_encrypted_secret_path)?.read_to_end(&mut encrypted_secret_payload_from_file)?;
    std::fs::remove_file(&temp_encrypted_secret_path)?; // Видаляємо тимчасовий файл
    logger.verbose(&format!("Тимчасовий зашифрований файл прочитано ({} байт) та видалено.", encrypted_secret_payload_from_file.len()));


    // Формуємо повний блок даних для приховування в зображенні
    let mut data_to_hide_in_image = Vec::new();
    data_to_hide_in_image.extend_from_slice(STEGO_SIGNATURE); // 4 байти
    // Довжина всього наступного блоку (encrypted_secret_payload_from_file)
    data_to_hide_in_image.extend_from_slice(&(encrypted_secret_payload_from_file.len() as u64).to_le_bytes()); // 8 байт
    data_to_hide_in_image.extend_from_slice(&encrypted_secret_payload_from_file);

    logger.verbose(&format!("Загальний розмір даних для LSB-приховування (сигнатура+довжина+шифрований_секрет_з_метаданими): {} байт.", data_to_hide_in_image.len()));

    // Приховуємо дані в зображенні
    hide_data_in_image_pixels_actual(cover_image_input_path, &data_to_hide_in_image, stego_image_output_path, logger)?;

    logger.info(&format!("Дані успішно приховано та збережено як '{}' (оригінальний контейнер змінено)", stego_image_output_path));
    Ok(())
}


fn handle_steg_extract(cli: &Cli, logger: &Logger) -> Result<(), CryptoError> {
    let stego_image_path = cli.file_path.as_ref()
        .ok_or_else(|| CryptoError::InvalidData("Для 'steg-extract' не вказано стего-зображення (-f).".to_string()))?;
    let output_secret_path = cli.output.as_ref()
        .ok_or_else(|| CryptoError::InvalidData("Для 'steg-extract' не вказано шлях вихідного файлу (-o).".to_string()))?;

    logger.info(&format!("[STEG EXTRACT] Завдання: вилучити з '{}' у '{}'", stego_image_path, output_secret_path));

    // 1. Вилучаємо весь прихований блок даних з зображення
    let hidden_data_block_with_header = extract_all_hidden_data_from_image_pixels_actual(stego_image_path, logger)?;
    logger.verbose(&format!("Вилучено загалом {} байт з зображення (включаючи стего-заголовок).", hidden_data_block_with_header.len()));

    // 2. Перевіряємо сигнатуру та вилучаємо довжину
    let mut current_offset = 0;
    if hidden_data_block_with_header.len() < STEGO_SIGNATURE.len() + 8 { // Сигнатура + довжина (u64)
        return Err(CryptoError::InvalidData("Вилучено занадто мало даних для стего-заголовка.".to_string()));
    }
    if &hidden_data_block_with_header[..STEGO_SIGNATURE.len()] != STEGO_SIGNATURE {
        return Err(CryptoError::InvalidData("Не знайдено дійсну стего-сигнатуру.".to_string()));
    }
    logger.verbose("Стего-сигнатура підтверджена.");
    current_offset += STEGO_SIGNATURE.len();

    let encrypted_secret_payload_len_bytes_slice = hidden_data_block_with_header.get(current_offset .. current_offset + 8)
        .ok_or(CryptoError::InvalidData("Не вдалося прочитати довжину зашифрованого секрету.".to_string()))?;
    let encrypted_secret_payload_len = u64::from_le_bytes(encrypted_secret_payload_len_bytes_slice.try_into().unwrap()) as usize;
    current_offset += 8;

    logger.verbose(&format!("Очікувана довжина зашифрованого секрету (з його метаданими шифрування): {} байт.", encrypted_secret_payload_len));

    let encrypted_secret_payload_slice = hidden_data_block_with_header.get(current_offset .. current_offset + encrypted_secret_payload_len)
        .ok_or(CryptoError::InvalidData("Не вдалося прочитати повний зашифрований секрет з вилученого блоку.".to_string()))?;

    // 3. Зберігаємо цей encrypted_secret_payload_slice у тимчасовий файл
    let temp_encrypted_secret_path_for_decryption = format!("{}.temp_steg_payload_{}", output_secret_path, SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()); // Додаємо унікальність
    {
        let mut temp_file = File::create(&temp_encrypted_secret_path_for_decryption)?;
        temp_file.write_all(encrypted_secret_payload_slice)?;
        logger.verbose(&format!("Зашифрований секрет ({} байт) збережено у тимчасовий файл: {}", encrypted_secret_payload_slice.len(), temp_encrypted_secret_path_for_decryption));
    }
    
    let result = decrypt_file(
        &temp_encrypted_secret_path_for_decryption, 
        &cli.algorithm, // Алгоритм для дешифрування (має збігатися з тим, що у файлі, decrypt_file це перевірить)
        &Some(output_secret_path.clone()), // Куди зберегти фінальний дешифрований секрет
        logger, 
        cli 
    );

    // 5. Видаляємо тимчасовий файл незалежно від результату дешифрування
    if let Err(e) = std::fs::remove_file(&temp_encrypted_secret_path_for_decryption) {
        logger.error(&format!("Не вдалося видалити тимчасовий файл '{}': {}", temp_encrypted_secret_path_for_decryption, e));
    }

    result?; // Повертаємо результат decrypt_file
    logger.info(&format!("Дані успішно вилучено, дешифровано та збережено як '{}'", output_secret_path));
    Ok(())
}


fn hide_data_in_image_pixels_actual(
    cover_image_input_path: &str,
    data_to_hide: &[u8],
    stego_image_output_path: &str,
    logger: &Logger,
) -> Result<(), CryptoError> {
    logger.verbose(&format!(
        "[LSB HIDE] Завантаження зображення-контейнера: {}",
        cover_image_input_path
    ));

    // 1. Завантажуємо зображення
    let img_dynamic = match ImageReader::open(cover_image_input_path) {
        Ok(reader) => match reader.with_guessed_format()?.decode() {
            Ok(decoded_img) => decoded_img,
            Err(e) => {
                return Err(CryptoError::InvalidData(format!(
                    "Помилка декодування зображення-контейнера '{}': {}",
                    cover_image_input_path, e
                )));
            }
        },
        Err(e) => return Err(CryptoError::IoError(e)), // Помилка відкриття файлу
    };

    let (width, height) = img_dynamic.dimensions();
    // Кожен піксель має 3 колірні компоненти (R, G, B), у які ми можемо записати по 1 біту.
    let max_hideable_bits = width as usize * height as usize * 3; // 3 біти на піксель (R, G, B)
    let required_bits = data_to_hide.len() * BITS_PER_BYTE;

    if required_bits > max_hideable_bits {
        return Err(CryptoError::InvalidData(format!(
            "Зображення занадто мале для приховування даних. Потрібно {} біт, доступно (RGB) ~{} біт",
            required_bits, max_hideable_bits
        )));
    }
    logger.verbose(&format!(
        "[LSB HIDE] Доступно ~{} біт, потрібно {} біт. Коефіцієнт заповнення: {:.2}%",
        max_hideable_bits,
        required_bits,
        (required_bits as f64 / max_hideable_bits as f64) * 100.0
    ));

    // Для модифікації пікселів нам потрібен мутабельний буфер.
    let mut img_buffer = img_dynamic.to_rgba8(); // Працюємо з RGBA буфером

    let mut data_bit_iter = data_to_hide
        .iter()
        .flat_map(|byte_val| (0..BITS_PER_BYTE).map(move |i| (byte_val >> (7 - i)) & 1));
    
    let mut bits_written_count = 0;

    'pixel_loop: for y in 0..height {
        for x in 0..width {
            let pixel = img_buffer.get_pixel_mut(x, y); // Отримуємо мутабельний доступ до пікселя Rgba<u8>
            // pixel.0 - це масив [R, G, B, A]

            // Канал R
            if let Some(bit_to_hide) = data_bit_iter.next() {
                pixel.0[0] = (pixel.0[0] & 0xFE) | bit_to_hide;
                bits_written_count += 1;
            } else {
                break 'pixel_loop; // Всі біти даних приховано
            }

            // Канал G
            if let Some(bit_to_hide) = data_bit_iter.next() {
                pixel.0[1] = (pixel.0[1] & 0xFE) | bit_to_hide;
                bits_written_count += 1;
            } else {
                break 'pixel_loop;
            }

            // Канал B
            if let Some(bit_to_hide) = data_bit_iter.next() {
                pixel.0[2] = (pixel.0[2] & 0xFE) | bit_to_hide;
                bits_written_count += 1;
            } else {
                break 'pixel_loop;
            }
            // Альфа-канал (pixel.0[3]) ми не чіпаємо.
        }
    }

    logger.verbose(&format!(
        "[LSB HIDE] Фактично записано {} біт у зображення.",
        bits_written_count
    ));

    if bits_written_count < required_bits {
        return Err(CryptoError::InvalidData(format!(
            "Не вдалося приховати всі дані: записано {} біт, потрібно було {}.",
            bits_written_count, required_bits
        )));
    }

    // Зберігаємо змінене зображення
    img_buffer.save(stego_image_output_path).map_err(|e| {
        CryptoError::IoError(io::Error::new(
            io::ErrorKind::Other,
            format!("Помилка збереження стего-зображення '{}': {}", stego_image_output_path, e),
        ))
    })?;

    logger.info(&format!(
        "Дані успішно приховано. Стего-зображення збережено як '{}'",
        stego_image_output_path
    ));
    Ok(())
}

// Допоміжний ітератор для читання біт з LSB пікселів
struct LsbBitIterator<'a> {
    img_buffer: &'a image::ImageBuffer<Rgba<u8>, Vec<u8>>, // Повний шлях до ImageBuffer
    width: u32,
    height: u32,
    current_x: u32,
    current_y: u32,
    current_channel: u8, // 0 for R, 1 for G, 2 for B
}

impl<'a> LsbBitIterator<'a> {
    fn new(img_buffer: &'a image::ImageBuffer<Rgba<u8>, Vec<u8>>) -> Self { // Повний шлях
        let (width, height) = img_buffer.dimensions();
        LsbBitIterator {
            img_buffer,
            width,
            height,
            current_x: 0,
            current_y: 0,
            current_channel: 0,
        }
    }
}

impl<'a> Iterator for LsbBitIterator<'a> {
    type Item = u8; // Повертаємо один біт (0 або 1)

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_y >= self.height {
            return None; // Досягли кінця зображення
        }

        let pixel = self.img_buffer.get_pixel(self.current_x, self.current_y);
        let bit = pixel.0[self.current_channel as usize] & 1;

        self.current_channel += 1;
        if self.current_channel > 2 { // Обробили R, G, B
            self.current_channel = 0;
            self.current_x += 1;
            if self.current_x >= self.width {
                self.current_x = 0;
                self.current_y += 1;
            }
        }
        Some(bit)
    }
}

// Допоміжна функція для читання одного байта з LSB ітератора
fn read_byte_from_lsb_iter<'a>(
    bit_iter: &mut LsbBitIterator<'a>,
) -> Result<u8, CryptoError> {
    let mut byte_value = 0u8;
    for _ in 0..BITS_PER_BYTE { // Використовуємо _ замість i
        match bit_iter.next() {
            Some(bit) => {
                byte_value = (byte_value << 1) | bit;
            }
            None => {
                return Err(CryptoError::InvalidData(
                    "Несподіваний кінець даних зображення при спробі зібрати байт.".to_string(),
                ));
            }
        }
    }
    Ok(byte_value)
}


fn extract_all_hidden_data_from_image_pixels_actual(
    stego_image_path: &str,
    logger: &Logger,
) -> Result<Vec<u8>, CryptoError> {
    logger.verbose(&format!(
        "[LSB EXTRACT] Завантаження стего-зображення: {}",
        stego_image_path
    ));

    let img_dynamic = match ImageReader::open(stego_image_path) {
        Ok(reader) => match reader.with_guessed_format()?.decode() {
            Ok(decoded_img) => decoded_img,
            Err(e) => {
                return Err(CryptoError::InvalidData(format!(
                    "Помилка декодування стего-зображення '{}': {}",
                    stego_image_path, e
                )));
            }
        },
        Err(e) => return Err(CryptoError::IoError(e)),
    };

    let img_buffer = img_dynamic.to_rgba8();
    
    let mut extracted_bytes_iter = LsbBitIterator::new(&img_buffer);

    // 1. Читаємо сигнатуру (STEGO_SIGNATURE.len() байт)
    let mut signature_bytes = Vec::with_capacity(STEGO_SIGNATURE.len());
    for _ in 0..STEGO_SIGNATURE.len() {
        signature_bytes.push(read_byte_from_lsb_iter(&mut extracted_bytes_iter)?);
    }

    if signature_bytes != STEGO_SIGNATURE {
        return Err(CryptoError::InvalidData(
            "Не знайдено дійсну стего-сигнатуру на початку даних.".to_string(),
        ));
    }
    logger.verbose("[LSB EXTRACT] Стего-сигнатура підтверджена.");

    // 2. Читаємо довжину всього зашифрованого блоку даних (u64 - 8 байт)
    let mut len_of_full_encrypted_block_bytes_vec = Vec::with_capacity(8);
    for _ in 0..8 { // u64 займає 8 байт
        len_of_full_encrypted_block_bytes_vec.push(read_byte_from_lsb_iter(&mut extracted_bytes_iter)?);
    }
    // Конвертуємо Vec<u8> в [u8; 8]
    let len_of_full_encrypted_block_bytes_array: [u8; 8] = len_of_full_encrypted_block_bytes_vec.try_into()
        .map_err(|_| CryptoError::InvalidData("Помилка конвертації довжини блоку (неправильний розмір вектора).".to_string()))?;
    let len_of_full_encrypted_block = u64::from_le_bytes(len_of_full_encrypted_block_bytes_array) as usize;

    logger.verbose(&format!(
        "[LSB EXTRACT] Очікувана довжина повного зашифрованого блоку (з його метаданими шифрування): {} байт.",
        len_of_full_encrypted_block
    ));
    
    // 3. Читаємо сам зашифрований блок даних
    let mut full_encrypted_block_bytes = Vec::with_capacity(len_of_full_encrypted_block);
    for _ in 0..len_of_full_encrypted_block {
        full_encrypted_block_bytes.push(read_byte_from_lsb_iter(&mut extracted_bytes_iter)?);
    }

    if full_encrypted_block_bytes.len() != len_of_full_encrypted_block {
        // Це може статися, якщо зображення закінчилося раніше, ніж ми прочитали заявлену довжину
        return Err(CryptoError::InvalidData(format!(
            "Не вдалося прочитати повний зашифрований блок: очікувалося {} байт, прочитано {}.",
            len_of_full_encrypted_block, full_encrypted_block_bytes.len()
        )));
    }

    logger.verbose(&format!(
        "[LSB EXTRACT] Вилучено {} байт зашифрованого блоку.",
        full_encrypted_block_bytes.len()
    ));
    
    // Збираємо все разом: сигнатура + байти_довжини + сам_блок
    // Це те, що буде парсити handle_steg_extract
    let mut final_hidden_data_block = Vec::new();
    final_hidden_data_block.extend_from_slice(STEGO_SIGNATURE);
    final_hidden_data_block.extend_from_slice(&len_of_full_encrypted_block_bytes_array); // Зберігаємо самі байти довжини
    final_hidden_data_block.extend_from_slice(&full_encrypted_block_bytes);

    Ok(final_hidden_data_block)
}

fn handle_generate_key(cli: &Cli, logger: &Logger) -> Result<(), CryptoError> {
    logger.info(&format!("[GEN KEY] Генерація нового ключа для алгоритму: {}", cli.algorithm));

    let new_key = generate_random_key(&cli.algorithm)?; //
    logger.verbose("[GEN KEY] Випадковий ключ успішно згенеровано.");

    if let Some(output_key_path) = &cli.output { // Використовуємо -o для шляху збереження
        if cli.use_password {
            // Зберігаємо згенерований ключ у файл, захищений паролем
            // Використовується та сама функція, що й при -S + -p для шифрування
            save_password_protected_key_file(&new_key, output_key_path, logger)?; //
            logger.info(&format!("[GEN KEY] Ключ зашифровано паролем та збережено у файл: {}", output_key_path));
        } else {
            // Зберігаємо ключ у файл у відкритому (шістнадцятковому) вигляді
            save_key_to_file(&new_key, output_key_path, logger)?; //
            logger.info(&format!("[GEN KEY] Ключ збережено у файл (шістнадцятковий формат): {}", output_key_path));
        }
    } else {
        // Якщо шлях для збереження (-o) не вказано, виводимо ключ в консоль
        let key_hex = hex::encode(new_key.expose_secret());
        if !logger.silent { // Перевіряємо, чи не в тихому режимі для додаткових повідомлень
            println!("\nЗгенерований ключ (hex): {}", key_hex);
            println!("Увага: Ключ виведено на екран. Для безпечного використання збережіть його у файл (бажано захищений паролем) за допомогою опції -o.");
        } else {
             println!("{}", key_hex); // Просто ключ, якщо silent і немає -o
        }
    }
    Ok(())
}
