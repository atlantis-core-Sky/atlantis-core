use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use base64::Engine;
use rand::Rng;

/// Clave de cifrado (32 bytes) - EXACTAMENTE 32 BYTES
const KEY: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";

/// Cifra un texto plano usando AES-256-GCM
pub fn encrypt(plaintext: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = Key::<Aes256Gcm>::from_slice(KEY);
    let cipher = Aes256Gcm::new(key);
    
    // Generar nonce aleatorio de 12 bytes
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Cifrar
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    // Construir: nonce + ciphertext
    let mut encrypted = nonce_bytes.to_vec();
    encrypted.extend(ciphertext);
    
    // Codificar en base64
    Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
}

/// Descifra un texto cifrado (formato: base64(nonce + ciphertext))
pub fn decrypt(encrypted: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = Key::<Aes256Gcm>::from_slice(KEY);
    let cipher = Aes256Gcm::new(key);
    
    // Decodificar base64
    let data = base64::engine::general_purpose::STANDARD.decode(encrypted)?;
    
    if data.len() < 28 {
        return Err("Datos muy cortos para ser válidos".into());
    }
    
    // Extraer nonce (12 bytes)
    let nonce = Nonce::from_slice(&data[..12]);
    
    // El resto es ciphertext + tag (16 bytes de tag al final)
    let ciphertext_with_tag = &data[12..];
    
    // Descifrar
    let plaintext = cipher.decrypt(nonce, ciphertext_with_tag)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    
    Ok(String::from_utf8(plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        let original = "Hola mundo, este es un texto de prueba";
        let encrypted = encrypt(original).unwrap();
        let decrypted = decrypt(&encrypted).unwrap();
        assert_eq!(original, decrypted);
    }
    
    #[test]
    fn test_decrypt_plain_json() {
        let plain_json = r#"{"test":"value"}"#;
        let result = decrypt(plain_json);
        assert!(result.is_err());
    }
}
