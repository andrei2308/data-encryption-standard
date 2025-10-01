import dataEncryptionStandard.DES;
import dataEncryptionStandard.Utils;

import java.util.Scanner;

/**
 * Main class for demonstrating DES encryption and decryption functionality.
 * <p>
 * This interactive program allows users to encrypt plaintext using the Data
 * Encryption Standard (DES) algorithm with a user-provided key, and then
 * decrypt the ciphertext back to verify the implementation works correctly.
 * <p>
 * <b>Program Flow:</b>
 * <ol>
 *   <li>Prompts user to enter plaintext (any ASCII string)</li>
 *   <li>Prompts user to enter a 64-bit encryption key as 16 hexadecimal characters</li>
 *   <li>Encrypts the plaintext using DES with PKCS#7 padding</li>
 *   <li>Displays the encrypted ciphertext in hexadecimal format</li>
 *   <li>Decrypts the ciphertext back to the original plaintext</li>
 *   <li>Displays the decrypted result to verify correctness</li>
 * </ol>
 * <p>
 * <b>Key Format Requirements:</b>
 * <ul>
 *   <li>Must be exactly 16 hexadecimal characters (0-9, A-F)</li>
 *   <li>Represents 64 bits (8 bytes) of key material</li>
 *   <li>Example: "133457799BBCDFF1"</li>
 *   <li>Case-insensitive (both "AABBCC" and "aabbcc" are valid)</li>
 * </ul>
 * <p>
 * <b>Security Warning:</b> DES is cryptographically weak by modern standards
 * due to its 56-bit effective key size. This implementation is for educational
 * purposes and should not be used to protect sensitive data in production
 * environments. Consider using AES instead for real-world applications.
 * <p>
 * <b>Example Usage:</b>
 * <pre>
 * Enter the plain text:
 * Hello World!
 * Enter the key in hex (16 characters):
 * 133457799BBCDFF1
 * Encrypted (hex): 85E813540F0AB405B1C6827656A1C6D6
 * Decrypted (text): Hello World!
 * </pre>
 * <p>
 * <b>Note on Padding:</b> The encrypted output may be longer than the input
 * because PKCS#7 padding is automatically applied to make the plaintext a
 * multiple of 8 bytes (DES block size). The padding is automatically removed
 * during decryption.
 *
 * @author Chitoiu Andrei
 * @version 2.0
 * @see DES
 * @see Utils
 */
public class Main {
    /**
     * Main entry point for the DES encryption/decryption demonstration program.
     * <p>
     * This method orchestrates the complete encryption and decryption workflow:
     * <ol>
     *   <li><b>Input Collection:</b> Gathers plaintext and hexadecimal key from user</li>
     *   <li><b>Encryption Phase:</b>
     *     <ul>
     *       <li>Converts plaintext string to byte array</li>
     *       <li>Converts hex key string to byte array</li>
     *       <li>Creates DES cipher instance with plaintext and key</li>
     *       <li>Encrypts using DES algorithm (includes automatic PKCS#7 padding)</li>
     *       <li>Displays resulting ciphertext in hexadecimal format</li>
     *     </ul>
     *   </li>
     *   <li><b>Decryption Phase:</b>
     *     <ul>
     *       <li>Converts hex ciphertext back to byte array</li>
     *       <li>Creates new DES cipher instance with ciphertext and same key</li>
     *       <li>Decrypts using DES algorithm (includes automatic padding removal)</li>
     *       <li>Displays recovered plaintext as ASCII string</li>
     *     </ul>
     *   </li>
     * </ol>
     * <p>
     * <b>Input Validation:</b> This implementation does not validate input format.
     * For production use, you should add validation for:
     * <ul>
     *   <li>Key length (must be exactly 16 hex characters)</li>
     *   <li>Key characters (must be valid hexadecimal: 0-9, A-F, a-f)</li>
     *   <li>Empty plaintext handling</li>
     *   <li>Character encoding issues</li>
     * </ul>
     * <p>
     * <b>Error Handling:</b> The program may throw exceptions if:
     * <ul>
     *   <li>The key is not valid hexadecimal or wrong length</li>
     *   <li>The decryption key doesn't match the encryption key</li>
     *   <li>The ciphertext is corrupted or modified</li>
     * </ul>
     * <p>
     * <b>Example Execution:</b>
     * <pre>
     * // User input
     * Plain text: "Secret Message"
     * Key: "0123456789ABCDEF"
     *
     * // Program output
     * Encrypted (hex): A1B2C3D4E5F67890...
     * Decrypted (text): Secret Message
     * </pre>
     * <p>
     * <b>Technical Details:</b>
     * <ul>
     *   <li>Uses UTF-8 encoding for string to byte conversion (default)</li>
     *   <li>Plaintext of any length is supported (padding applied automatically)</li>
     *   <li>Output ciphertext length is always a multiple of 16 hex chars (8 bytes)</li>
     *   <li>Same key must be used for encryption and decryption</li>
     * </ul>
     * <p>
     * <b>Why Two DES Instances?</b><br>
     * The implementation creates separate DES instances for encryption and decryption
     * because the DES constructor takes the data to be processed (plaintext for
     * encryption, ciphertext for decryption) as a parameter. This design treats
     * DES as a stateless operation on fixed data.
     *
     * @param args command line arguments (not used in this implementation)
     * @throws NumberFormatException if the key contains invalid hexadecimal characters
     * @throws RuntimeException if padding validation fails during decryption
     * @see DES#encrypt()
     * @see DES#decrypt()
     * @see Utils#hexStringToBytes(String)
     */
    public static void main(String[] args) {
        // Create scanner for reading user input from console
        Scanner scanner = new Scanner(System.in);

        // ===== STEP 1: Get plaintext input from user =====
        // The plaintext can be any ASCII string of any length
        // PKCS#7 padding will be automatically applied during encryption
        System.out.println("Enter the plain text: ");
        String plainText = scanner.nextLine();

        // ===== STEP 2: Get encryption key in hexadecimal format =====
        // Key must be exactly 16 hex characters representing 64 bits (8 bytes)
        // Examples: "133457799BBCDFF1", "AABBCCDDEEFF0011"
        // DES uses 56 bits for encryption; 8 bits are parity bits
        System.out.println("Enter the key in hex (16 characters): ");
        String keyHex = scanner.nextLine();

        // ===== STEP 3: Encrypt the plaintext =====
        // Convert plaintext string to byte array using default encoding (UTF-8)
        byte[] plainTextBytes = plainText.getBytes();

        // Convert hex key string to byte array
        // Example: "133457799BBCDFF1" → [13, 34, 57, 79, 9B, BC, DF, F1]
        byte[] keyBytes = Utils.hexStringToBytes(keyHex);

        // Create DES cipher instance for encryption
        // The cipher is initialized with plaintext and key
        DES des = new DES(plainTextBytes, keyBytes);

        // Perform encryption
        // This applies PKCS#7 padding, runs 16 rounds of DES, and returns hex string
        String encrypted = des.encrypt();

        // ===== STEP 4: Display encrypted result =====
        // The result is shown in hexadecimal format for readability
        // Length will be a multiple of 16 hex chars (8 bytes = 1 DES block)
        System.out.println("Encrypted (hex): " + encrypted);

        // ===== STEP 5: Decrypt the ciphertext =====
        // Convert hex ciphertext back to byte array for decryption
        byte[] encryptedBytes = Utils.hexStringToBytes(encrypted);

        // Create new DES cipher instance for decryption
        // Note: We use the SAME key as encryption, but pass ciphertext as data
        DES desDecrypt = new DES(encryptedBytes, keyBytes);

        // Perform decryption
        // This runs 16 rounds with reversed key order, then removes PKCS#7 padding
        String decrypted = desDecrypt.decrypt();

        // ===== STEP 6: Display decrypted result =====
        // If everything worked correctly, this should match the original plaintext
        System.out.println("Decrypted (text): " + decrypted);

        // Close scanner to prevent resource leak
        scanner.close();

        // Note: In a production application, you would:
        // 1. Validate all inputs before processing
        // 2. Use try-catch blocks for proper error handling
        // 3. Clear sensitive data (key, plaintext) from memory after use
        // 4. Use a stronger algorithm like AES instead of DES
        // 5. Consider using a proper key derivation function (KDF) for user passwords
    }
}