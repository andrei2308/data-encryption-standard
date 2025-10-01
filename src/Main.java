import dataEncryptionStandard.DES;
import dataEncryptionStandard.Utils;

import java.util.Scanner;

/**
 * Main class for demonstrating DES encryption and decryption.
 * This program encrypts user-provided plaintext using a hexadecimal key,
 * then decrypts it back to verify the implementation.
 *
 * @author Chitoiu Andrei
 */
public class Main {
    /**
     * Main method that handles user input and demonstrates DES encryption/decryption.
     * <p>
     * Process:
     * @1. Accepts plaintext as ASCII string input from user
     * @2. Accepts encryption key as 16-character hexadecimal string (64 bits)
     * @3. Encrypts the plaintext using DES algorithm
     * @4. Displays the encrypted result in hexadecimal format
     * @5. Decrypts the ciphertext back to original plaintext
     * @6. Displays the decrypted result as ASCII text
     *
     * @param args command line arguments (not used)
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Get plaintext input from user
        System.out.println("Enter the plain text: ");
        String plainText = scanner.nextLine();

        if (plainText.length() != 8) {
            throw new IllegalArgumentException("No padding supported yet, input should be exactly 8 bytes, 64 bits.");
        }

        // Get encryption key in hexadecimal format (must be 16 hex characters = 64 bits)
        System.out.println("Enter the key in hex (16 characters): ");
        String keyHex = scanner.nextLine();

        if (keyHex.length() != 16) {
            throw new IllegalArgumentException("Key must be 8 bytes long, 64 bits");
        }

        // Encrypt the plaintext
        byte[] plainTextBytes = plainText.getBytes();
        DES des = new DES(plainTextBytes, Utils.hexStringToBytes(keyHex));
        String encrypted = des.encrypt();

        // Display encrypted result
        System.out.println("Encrypted (hex): " + encrypted);

        // Decrypt the ciphertext
        byte[] encryptedBytes = Utils.hexStringToBytes(encrypted);
        DES desDecrypt = new DES(encryptedBytes, Utils.hexStringToBytes(keyHex));
        String decrypted = desDecrypt.decrypt();

        // Display decrypted result
        System.out.println("Decrypted (text): " + decrypted);
    }
}