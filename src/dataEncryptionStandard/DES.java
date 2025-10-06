package dataEncryptionStandard;

import javax.crypto.spec.IvParameterSpec;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static dataEncryptionStandard.Utils.*;

/**
 * Implementation of the Data Encryption Standard (DES) algorithm with CBC mode support.
 * <p>
 * DES is a symmetric-key block cipher that encrypts 64-bit blocks of data
 * using a 56-bit key through 16 rounds of Feistel network operations.
 * It was adopted as a federal standard in 1977 and remained widely used
 * until it was superseded by AES in 2001.
 * <p>
 * <b>Block size:</b> 64 bits (8 bytes)<br>
 * <b>Key size:</b> 56 bits effective (64 bits with 8 parity bits)<br>
 * <b>Rounds:</b> 16 Feistel rounds<br>
 * <b>Mode of operation:</b> CBC (Cipher Block Chaining)
 * <p>
 * <b>Multi-block processing:</b> This implementation handles data of any length
 * by splitting it into 8-byte blocks after padding. Each block is encrypted
 * using CBC mode, where each plaintext block is XORed with the previous ciphertext
 * block before encryption. This provides better security than ECB mode.
 * <p>
 * <b>Padding:</b> This implementation uses PKCS#7 padding to handle plaintext
 * that is not a multiple of the 8-byte block size. The padding is automatically
 * added during encryption and removed during decryption. Users do not need to
 * manually pad their input data.
 * <p>
 * <b>Security note:</b> DES is considered cryptographically weak by modern
 * standards due to its small key size. This implementation should only be used
 * for educational purposes. For production systems, use AES with GCM or CBC mode.
 * <p>
 * <b>Thread safety:</b> This class is not thread-safe. Create separate instances
 * for concurrent encryption/decryption operations.
 * <p>
 * <b>Usage example:</b>
 * <pre>
 * byte[] plaintext = "Hello World".getBytes();
 * byte[] key = hexStringToBytes("133457799BBCDFF1");
 *
 * DES des = new DES(plaintext, key);
 * String encrypted = des.encrypt();
 *
 * DES des2 = new DES(hexStringToBytes(encrypted), key);
 * des2.setIvBits(des.getIvBits()); // Transfer IV for decryption
 * String decrypted = des2.decrypt();
 * </pre>
 *
 * @author Chitoiu Andrei
 * @version 3.0
 * @see <a href="https://en.wikipedia.org/wiki/Data_Encryption_Standard">DES on Wikipedia</a>
 */
public class DES {
    /**
     * The plaintext or ciphertext data to be processed.
     * <p>
     * For encryption, this contains the original plaintext.
     * For decryption, this contains the ciphertext to be decrypted.
     * <p>
     * The data can be of any length; PKCS#7 padding will be applied
     * automatically during encryption to make it a multiple of 8 bytes.
     */
    private final byte[] data;

    /**
     * The 64-bit encryption/decryption key (with 8 parity bits).
     * <p>
     * DES uses a 64-bit key, but only 56 bits are used for encryption.
     * The remaining 8 bits (one per byte) are parity bits that can be
     * used for error detection but are ignored during encryption.
     * <p>
     * The key should be 8 bytes (64 bits) in length. If provided as a
     * hexadecimal string, it should be 16 hex characters.
     */
    private final byte[] key;

    /**
     * The Initialization Vector (IV) used for CBC mode encryption/decryption.
     * <p>
     * The IV is a 64-bit (8-byte) random value used to initialize CBC mode.
     * It ensures that encrypting the same plaintext multiple times produces
     * different ciphertexts, preventing pattern analysis.
     * <p>
     * For encryption: automatically generated using SecureRandom.
     * For decryption: must be set to the same IV used during encryption.
     */
    private int[] ivBits;

    /**
     * Constructs a DES cipher instance with the given plaintext/ciphertext and key.
     * <p>
     * This constructor initializes the DES cipher with the data to be processed
     * and the encryption/decryption key. The same constructor is used for both
     * encryption and decryption operations.
     * <p>
     * <b>For encryption:</b> Pass the plaintext as the first parameter.<br>
     * <b>For decryption:</b> Pass the ciphertext (as bytes) as the first parameter
     * and ensure to set the IV using {@link #setIvBits(int[])} before calling decrypt.
     * <p>
     * The key must be exactly 8 bytes (64 bits) in length. DES will use 56 bits
     * of this key for encryption, ignoring the parity bits.
     *
     * @param data the input data to be encrypted or decrypted
     *             (can be any length; padding will be applied if needed)
     * @param key  the 64-bit key (8 bytes) used for encryption/decryption
     * @throws NullPointerException if data or key is null
     */
    public DES(byte[] data, byte[] key) {
        this.data = data;
        this.key = key;
    }

    /**
     * Encrypts the plaintext using the DES algorithm in CBC mode.
     * <p>
     * This method performs the complete DES encryption process for data of any length:
     * <ol>
     *   <li>Add PKCS#7 padding to make plaintext a multiple of 8 bytes</li>
     *   <li>Generate 16 round keys from the master key</li>
     *   <li>Generate a random Initialization Vector (IV)</li>
     *   <li>Split the padded data into 8-byte blocks</li>
     *   <li>For each block:
     *     <ul>
     *       <li>XOR the plaintext block with the previous ciphertext block (or IV for first block)</li>
     *       <li>Apply initial permutation (IP) to rearrange the bits</li>
     *       <li>Split the permuted block into left and right halves (32 bits each)</li>
     *       <li>Apply 16 rounds of Feistel encryption with generated round keys</li>
     *       <li>Swap and combine the final left and right halves</li>
     *       <li>Apply final permutation (FP) to produce the ciphertext block</li>
     *     </ul>
     *   </li>
     *   <li>Concatenate all encrypted blocks</li>
     *   <li>Convert the result to a hexadecimal string</li>
     * </ol>
     * <p>
     * <b>CBC mode:</b> Each plaintext block is XORed with the previous ciphertext block
     * before encryption. The first block is XORed with the IV. This ensures that identical
     * plaintext blocks produce different ciphertext blocks, preventing pattern analysis.
     * <p>
     * <b>Output format:</b> The ciphertext is returned as a hexadecimal string
     * where each byte is represented by two hexadecimal characters. The length
     * of the output will always be a multiple of 16 characters (8 bytes per block).
     * <p>
     * <b>Examples:</b>
     * <pre>
     * Input:  "Hello" (5 bytes)
     * Padded: "Hello" + [03 03 03] (8 bytes after padding)
     * Blocks: 1 block of 8 bytes
     * Output: "85E813540F0AB405" (16 hex characters = 8 bytes)
     *
     * Input:  "Hello World!" (12 bytes)
     * Padded: "Hello World!" + [04 04 04 04] (16 bytes after padding)
     * Blocks: 2 blocks of 8 bytes each
     * Output: "85E813540F0AB405A1B2C3D4E5F67890" (32 hex characters = 16 bytes)
     * </pre>
     *
     * @return the encrypted ciphertext as a hexadecimal string (uppercase)
     * @see #decrypt()
     * @see #encryptBlock(byte[], int[][])
     * @see #addPKCS7Padding(byte[], int)
     */
    public String encrypt() {
        // Step 1: Add PKCS#7 padding to make data a multiple of block size (8 bytes)
        byte[] paddedData = addPKCS7Padding(data, 8);

        // Step 2: Generate 16 round keys from the master key (done once for all blocks)
        int[] keyBits = bytesToBits(key);
        int[][] roundKeys = generateRoundKeys(keyBits);

        // Step 3: Calculate number of 8-byte blocks
        int numBlocks = paddedData.length / 8;

        // Step 4: Prepare array to hold all encrypted blocks
        byte[] encryptedData = new byte[paddedData.length];

        // Step 5: Generate random IV for CBC mode
        generateIv();

        // Step 6: Process first block (XOR with IV)
        byte[] firstBlock = new byte[8];
        System.arraycopy(paddedData, 0, firstBlock, 0, 8);
        int[] firstBlockBits = bytesToBits(firstBlock);
        byte[] xoredFirstBlock = bitsToBytes(xor(this.ivBits, firstBlockBits));
        byte[] encryptedFirstBlock = encryptBlock(xoredFirstBlock, roundKeys);
        System.arraycopy(encryptedFirstBlock, 0, encryptedData, 0, 8);

        // Step 7: Encrypt remaining blocks (CBC mode - XOR with previous ciphertext)
        for (int blockIndex = 1; blockIndex < numBlocks; blockIndex++) {
            // Extract one 8-byte plaintext block
            byte[] currentBlock = new byte[8];
            System.arraycopy(paddedData, blockIndex * 8, currentBlock, 0, 8);

            // Get previous ciphertext block for XOR
            byte[] previousCipherBlock = new byte[8];
            System.arraycopy(encryptedData, (blockIndex - 1) * 8, previousCipherBlock, 0, 8);

            // XOR current plaintext with previous ciphertext (CBC chaining)
            byte[] xoredBlock = bitsToBytes(xor(bytesToBits(previousCipherBlock), bytesToBits(currentBlock)));

            // Encrypt the XORed block
            byte[] encryptedBlock = encryptBlock(xoredBlock, roundKeys);

            // Store encrypted block in result array
            System.arraycopy(encryptedBlock, 0, encryptedData, blockIndex * 8, 8);
        }

        // Step 8: Convert all encrypted bytes to hexadecimal string
        return bytesToHexString(encryptedData);
    }

    /**
     * Decrypts the ciphertext using the DES algorithm in CBC mode.
     * <p>
     * DES decryption is structurally identical to encryption with one key difference:
     * the round keys are applied in reverse order (from round 15 down to round 0).
     * This property is a result of the Feistel network structure, which makes
     * encryption and decryption processes symmetric.
     * <p>
     * The decryption process for multi-block data in CBC mode:
     * <ol>
     *   <li>Generate 16 round keys from the master key (same as encryption)</li>
     *   <li>Split the ciphertext into 8-byte blocks</li>
     *   <li>For each block:
     *     <ul>
     *       <li>Apply initial permutation (IP) to the ciphertext block</li>
     *       <li>Split permuted ciphertext into left and right halves</li>
     *       <li>Apply 16 rounds of Feistel decryption with <b>reversed</b> round keys</li>
     *       <li>Swap and combine the final left and right halves</li>
     *       <li>Apply final permutation (FP) to get intermediate result</li>
     *       <li>XOR with previous ciphertext block (or IV for first block) to get plaintext</li>
     *     </ul>
     *   </li>
     *   <li>Concatenate all decrypted blocks</li>
     *   <li>Remove PKCS#7 padding to recover the original plaintext</li>
     *   <li>Convert result back to a string</li>
     * </ol>
     * <p>
     * <b>Key reversal:</b> While the round keys are generated in the same way as
     * during encryption, they are applied in reverse order: K15, K14, ..., K1, K0.
     * This reverses the encryption process and recovers the original plaintext.
     * <p>
     * <b>CBC mode decryption:</b> After decrypting each block with DES, the result
     * is XORed with the previous ciphertext block (or IV for the first block) to
     * recover the original plaintext. This reverses the CBC chaining process.
     * <p>
     * <b>Padding removal:</b> After all blocks are decrypted, the PKCS#7 padding
     * is validated and removed. If the padding is invalid (indicating wrong key or
     * corrupted data), an exception will be thrown.
     * <p>
     * <b>Examples:</b>
     * <pre>
     * Input:  "85E813540F0AB405" (ciphertext as hex string converted to bytes)
     * Blocks: 1 block of 8 bytes
     * Output: "Hello" (original plaintext after padding removal)
     *
     * Input:  "85E813540F0AB405A1B2C3D4E5F67890" (32 hex characters)
     * Blocks: 2 blocks of 8 bytes each
     * Output: "Hello World!" (original plaintext after padding removal)
     * </pre>
     *
     * @return the decrypted plaintext as a string
     * @throws RuntimeException if padding is invalid (wrong key or corrupted data)
     * @throws RuntimeException if IV has not been set (call {@link #setIvBits(int[])} first)
     * @see #encrypt()
     * @see #decryptBlock(byte[], int[][])
     * @see #removePKCS7Padding(byte[])
     */
    public String decrypt() {
        // Validate that IV has been set
        if (ivBits == null) {
            throw new RuntimeException("IV must be set before decryption. Call setIvBits() first.");
        }

        // Step 1: Generate 16 round keys
        int[] keyBits = bytesToBits(key);
        int[][] roundKeys = generateRoundKeys(keyBits);

        // Step 2: Determine number of blocks
        int numBlocks = data.length / 8;
        byte[] decryptedData = new byte[data.length];

        // Step 3: Process first block (XOR with IV after decryption)
        byte[] firstCipherBlock = new byte[8];
        System.arraycopy(data, 0, firstCipherBlock, 0, 8);

        // Decrypt first ciphertext block
        byte[] decryptedFirstBlock = decryptBlock(firstCipherBlock, roundKeys);
        // XOR with IV to get plaintext
        byte[] firstPlainBlock = bitsToBytes(xor(bytesToBits(decryptedFirstBlock), this.ivBits));
        // Store plaintext
        System.arraycopy(firstPlainBlock, 0, decryptedData, 0, 8);

        // Step 4: Process subsequent blocks (CBC mode - XOR with previous ciphertext)
        for (int blockIndex = 1; blockIndex < numBlocks; blockIndex++) {
            byte[] currentCipherBlock = new byte[8];
            System.arraycopy(data, blockIndex * 8, currentCipherBlock, 0, 8);

            // Decrypt ciphertext block
            byte[] decryptedBlock = decryptBlock(currentCipherBlock, roundKeys);

            // XOR with previous ciphertext block to get plaintext (CBC unchaining)
            byte[] previousCipherBlock = new byte[8];
            System.arraycopy(data, (blockIndex - 1) * 8, previousCipherBlock, 0, 8);

            byte[] plainBlock = bitsToBytes(xor(bytesToBits(decryptedBlock), bytesToBits(previousCipherBlock)));

            // Store plaintext
            System.arraycopy(plainBlock, 0, decryptedData, blockIndex * 8, 8);
        }

        // Step 5: Remove padding
        byte[] unpaddedData = removePKCS7Padding(decryptedData);

        return new String(unpaddedData);
    }

    /**
     * Generates a random 64-bit Initialization Vector (IV) for CBC mode.
     * <p>
     * The IV is generated using SHA1PRNG (Secure Hash Algorithm 1 Pseudo-Random Number Generator)
     * which provides cryptographically strong random numbers suitable for cryptographic operations.
     * <p>
     * The generated IV is stored in {@link #ivBits} and must be transmitted along with
     * the ciphertext (or stored) so that the recipient can decrypt the message. The IV
     * does not need to be kept secret, but it must be unique for each encryption operation
     * with the same key.
     * <p>
     * <b>Security properties:</b>
     * <ul>
     *   <li>Random: unpredictable and different for each encryption</li>
     *   <li>Unique: should never be reused with the same key</li>
     *   <li>Public: does not need to be kept secret (but must be authentic)</li>
     * </ul>
     *
     * @throws RuntimeException if SHA1PRNG algorithm is not available
     */
    private void generateIv() {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] iv = new byte[8];
            random.nextBytes(iv);

            this.ivBits = bytesToBits(new IvParameterSpec(iv).getIV());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate IV: SHA1PRNG algorithm not available", e);
        }
    }

    /**
     * Encrypts a single 8-byte block using the DES algorithm.
     * <p>
     * This method performs the core DES encryption on exactly one 64-bit block.
     * It is called by the {@link #encrypt()} method for each block in the input data.
     * <p>
     * Process:
     * <ol>
     *   <li>Convert the 8-byte block to 64 bits</li>
     *   <li>Apply initial permutation (IP) to rearrange the bits</li>
     *   <li>Split into left and right halves (32 bits each)</li>
     *   <li>Apply 16 rounds of Feistel encryption:
     *     <ul>
     *       <li>newRight = left XOR Feistel(right, roundKey[i])</li>
     *       <li>left = right</li>
     *       <li>right = newRight</li>
     *     </ul>
     *   </li>
     *   <li>Combine right and left (swapped) into 64 bits</li>
     *   <li>Apply final permutation (FP)</li>
     *   <li>Convert 64 bits back to 8 bytes</li>
     * </ol>
     *
     * @param block     the 8-byte block to encrypt (must be exactly 8 bytes)
     * @param roundKeys the pre-generated 16 round keys (48 bits each)
     * @return the encrypted 8-byte block
     * @see #encrypt()
     * @see #feistel(int[], int[])
     */
    private byte[] encryptBlock(byte[] block, int[][] roundKeys) {
        // Step 1: Convert 8-byte block to 64-bit array
        int[] blockBits = bytesToBits(block);

        // Step 2: Apply initial permutation to rearrange bits
        int[] permutedBlock = permute(blockBits, Constants.initialPermutationTable);

        // Step 3: Split into left and right halves (32 bits each)
        int[][] LR = split(permutedBlock);
        int[] left = LR[0];   // L0: left 32 bits
        int[] right = LR[1];  // R0: right 32 bits

        // Step 4: Apply 16 rounds of Feistel encryption
        // Formula: Li = Ri-1, Ri = Li-1 XOR F(Ri-1, Ki)
        for (int round = 0; round < 16; round++) {
            int[] newRight = xor(left, feistel(right, roundKeys[round]));
            left = right;      // Li = Ri-1
            right = newRight;  // Ri = Li-1 XOR F(Ri-1, Ki)
        }

        // Step 5: Combine right and left (note: swapped from final round)
        // This "undo swap" is part of the Feistel structure
        int[] combined = combine(right, left);

        // Step 6: Apply final permutation (inverse of initial permutation)
        int[] cipherBits = permute(combined, Constants.finalPermutation);

        // Step 7: Convert 64-bit array back to 8-byte array
        return bitsToBytes(cipherBits);
    }

    /**
     * Decrypts a single 8-byte block using the DES algorithm.
     * <p>
     * This method performs the core DES decryption on exactly one 64-bit block.
     * It is called by the {@link #decrypt()} method for each block in the ciphertext.
     * <p>
     * Decryption is identical to encryption except that the round keys are applied
     * in reverse order (K15, K14, ..., K1, K0 instead of K0, K1, ..., K14, K15).
     * <p>
     * Process:
     * <ol>
     *   <li>Convert the 8-byte block to 64 bits</li>
     *   <li>Apply initial permutation (IP)</li>
     *   <li>Split into left and right halves (32 bits each)</li>
     *   <li>Apply 16 rounds of Feistel decryption with <b>reversed keys</b></li>
     *   <li>Combine right and left (swapped) into 64 bits</li>
     *   <li>Apply final permutation (FP)</li>
     *   <li>Convert 64 bits back to 8 bytes</li>
     * </ol>
     *
     * @param block     the 8-byte ciphertext block to decrypt (must be exactly 8 bytes)
     * @param roundKeys the pre-generated 16 round keys (48 bits each)
     * @return the decrypted 8-byte block (still includes padding if present)
     * @see #decrypt()
     * @see #feistel(int[], int[])
     */
    private byte[] decryptBlock(byte[] block, int[][] roundKeys) {
        // Step 1: Convert 8-byte block to 64-bit array
        int[] blockBits = bytesToBits(block);

        // Step 2: Apply initial permutation
        int[] permutedBlock = permute(blockBits, Constants.initialPermutationTable);

        // Step 3: Split into left and right halves
        int[][] LR = split(permutedBlock);
        int[] left = LR[0];
        int[] right = LR[1];

        // Step 4: Apply 16 rounds with round keys in REVERSE order
        // This is the key difference between encryption and decryption
        for (int round = 15; round >= 0; round--) {
            int[] newRight = xor(left, feistel(right, roundKeys[round]));
            left = right;
            right = newRight;
        }

        // Step 5: Combine right and left (swapped)
        int[] combined = combine(right, left);

        // Step 6: Apply final permutation
        int[] plainBits = permute(combined, Constants.finalPermutation);

        // Step 7: Convert 64-bit array back to 8-byte array
        return bitsToBytes(plainBits);
    }

    /**
     * Generates the 16 round keys from the master key.
     * <p>
     * DES uses a key schedule algorithm to derive 16 different 48-bit round keys
     * from the original 64-bit master key. This process ensures that each round
     * uses a different key, providing the confusion and diffusion necessary for
     * secure encryption.
     * <p>
     * The key generation process:
     * <ol>
     *   <li>Apply Permuted Choice 1 (PC-1) to reduce the 64-bit key to 56 bits
     *       by dropping the 8 parity bits</li>
     *   <li>Split the 56-bit key into two 28-bit halves (C0 and D0)</li>
     *   <li>For each of the 16 rounds:
     *     <ul>
     *       <li>Perform circular left shift on both C and D by 1 or 2 positions
     *           (according to the shift schedule)</li>
     *       <li>Combine the shifted C and D halves to form a 56-bit value</li>
     *       <li>Apply Permuted Choice 2 (PC-2) to select 48 bits from the 56-bit
     *           value, producing the round key</li>
     *     </ul>
     *   </li>
     * </ol>
     * <p>
     * <b>Shift schedule:</b> In rounds 1, 2, 9, and 16, both halves are shifted
     * left by 1 position. In all other rounds, they are shifted by 2 positions.
     * This ensures good key distribution across all rounds.
     * <p>
     * <b>PC-1 and PC-2:</b> These are fixed permutation tables defined in the
     * DES specification. PC-1 selects and rearranges 56 bits from the 64-bit key,
     * while PC-2 selects and rearranges 48 bits from the 56-bit shifted key.
     *
     * @param keyBits the 64-bit master key as a bit array
     * @return a 2D array containing 16 round keys, each 48 bits long
     * @see Constants#permutedChoice1
     * @see Constants#permutedChoice2
     * @see Constants#circularLeftShiftRounds
     */
    private int[][] generateRoundKeys(int[] keyBits) {
        // Step 1: Apply Permuted Choice 1 to get 56-bit key (dropping parity bits)
        int[] permutedKey = permute(keyBits, Constants.permutedChoice1);

        // Step 2: Split the 56-bit key into two 28-bit halves
        int[][] CD = split(permutedKey);
        int[] C = CD[0];  // C0: left 28 bits
        int[] D = CD[1];  // D0: right 28 bits

        // Array to store all 16 round keys
        int[][] roundKeys = new int[16][];

        // Step 3: Generate 16 round keys
        for (int round = 0; round < 16; round++) {
            // Perform circular left shift (1 or 2 positions based on round)
            C = leftShift(C, Constants.circularLeftShiftRounds[round]);
            D = leftShift(D, Constants.circularLeftShiftRounds[round]);

            // Combine shifted C and D to form 56-bit value
            int[] combinedCD = combine(C, D);

            // Apply Permuted Choice 2 to get 48-bit round key
            roundKeys[round] = permute(combinedCD, Constants.permutedChoice2);
        }

        return roundKeys;
    }

    /**
     * The Feistel function (F-function) - the core transformation of each DES round.
     * <p>
     * The Feistel function is the heart of the DES algorithm. It takes the 32-bit
     * right half of the data and a 48-bit round key as input, and produces a 32-bit
     * output through a series of transformations. This output is then XORed with
     * the left half to produce the new right half for the next round.
     * <p>
     * The Feistel function performs four main operations:
     * <ol>
     *   <li><b>Expansion (E):</b> Expands the 32-bit right half to 48 bits using
     *       the expansion permutation table. This is done by duplicating certain
     *       bits to match the 48-bit key size.</li>
     *   <li><b>Key Mixing:</b> XORs the expanded 48-bit value with the 48-bit
     *       round key. This combines the data with the key material.</li>
     *   <li><b>Substitution (S-boxes):</b> Passes the 48-bit result through 8
     *       S-boxes (substitution boxes), which provide non-linearity. Each S-box
     *       takes 6 bits as input and produces 4 bits as output, reducing the
     *       total from 48 bits to 32 bits.</li>
     *   <li><b>Permutation (P):</b> Applies a final permutation to the 32-bit
     *       S-box output using the straight permutation table. This diffuses
     *       the bits across the output.</li>
     * </ol>
     * <p>
     * <b>Security properties:</b>
     * <ul>
     *   <li>The S-boxes provide <i>confusion</i> - making the relationship between
     *       ciphertext and key complex</li>
     *   <li>The permutations provide <i>diffusion</i> - spreading the influence of
     *       each bit across many output bits</li>
     *   <li>The expansion ensures each key bit affects multiple output bits</li>
     * </ul>
     *
     * @param right    the 32-bit right half of the data block
     * @param roundKey the 48-bit round key for this round
     * @return 32-bit output after expansion, key mixing, substitution, and permutation
     * @see #applySBoxes(int[])
     * @see Constants#expansionTable
     * @see Constants#straightPermutationTable
     */
    private int[] feistel(int[] right, int[] roundKey) {
        // Step 1: Expand the 32-bit right half to 48 bits
        // This duplicates certain bits to match the round key size
        int[] expanded = permute(right, Constants.expansionTable);

        // Step 2: XOR the expanded value with the round key
        // This combines the data with the key material
        int[] xored = xor(expanded, roundKey);

        // Step 3: Apply S-boxes for substitution (48 bits -> 32 bits)
        // S-boxes provide non-linearity and confusion
        int[] sBoxOutput = applySBoxes(xored);

        // Step 4: Apply straight permutation (P-box) for diffusion
        // This spreads bit changes across the entire output
        return permute(sBoxOutput, Constants.straightPermutationTable);
    }

    /**
     * Applies the 8 S-boxes to convert 48 bits to 32 bits through substitution.
     * <p>
     * S-boxes (Substitution boxes) are the only non-linear component in DES and
     * are crucial for its security. They provide the <i>confusion</i> property
     * that makes the relationship between plaintext, ciphertext, and key complex
     * and difficult to analyze.
     * <p>
     * <b>How each S-box works:</b>
     * <ul>
     *   <li><b>Input:</b> 6 bits (numbered 0-5 from left to right)</li>
     *   <li><b>Row selection:</b> The outer bits (bit 0 and bit 5) form a 2-bit
     *       row number (0-3)</li>
     *   <li><b>Column selection:</b> The inner bits (bits 1-4) form a 4-bit
     *       column number (0-15)</li>
     *   <li><b>Lookup:</b> Use the row and column to look up a value in the
     *       S-box table (each table is 4 rows × 16 columns)</li>
     *   <li><b>Output:</b> The looked-up value (0-15) is converted to 4 bits</li>
     * </ul>
     * <p>
     * <b>Example for S-box 1:</b>
     * <pre>
     * Input:  [1 0 1 1 0 1]  (6 bits)
     * Row:    [1...1] = 11₂ = 3
     * Column: [0 1 1 0] = 0110₂ = 6
     * Lookup: S1[3][6] = 11
     * Output: [1 0 1 1]  (4 bits representing 11)
     * </pre>
     * <p>
     * <b>The complete process:</b>
     * <ol>
     *   <li>Split the 48-bit input into 8 groups of 6 bits</li>
     *   <li>Pass each 6-bit group through its corresponding S-box (S1-S8)</li>
     *   <li>Each S-box outputs 4 bits</li>
     *   <li>Concatenate all 8 outputs to form the 32-bit result</li>
     * </ol>
     * <p>
     * <b>Security properties:</b> The S-boxes are carefully designed to:
     * <ul>
     *   <li>Be resistant to differential cryptanalysis</li>
     *   <li>Be resistant to linear cryptanalysis</li>
     *   <li>Provide good avalanche effect (changing one input bit affects
     *       approximately half of the output bits)</li>
     *   <li>Have no fixed points or opposite fixed points</li>
     * </ul>
     *
     * @param input 48-bit input as an array of 8 groups of 6 bits each
     * @return 32-bit output as an array of 8 groups of 4 bits each
     * @see Constants#sBoxes
     */
    private int[] applySBoxes(int[] input) {
        // Output will be 32 bits (8 S-boxes × 4 bits each)
        int[] output = new int[32];

        // Process each of the 8 S-boxes
        for (int sBoxIndex = 0; sBoxIndex < 8; sBoxIndex++) {
            // Step 1: Extract 6 bits for this S-box
            int[] sixBits = new int[6];
            System.arraycopy(input, sBoxIndex * 6, sixBits, 0, 6);

            // Step 2: Calculate row from outer bits (first and last)
            // Row is formed by bit 0 (MSB) and bit 5 (LSB)
            int row = (sixBits[0] << 1) | sixBits[5];

            // Step 3: Calculate column from inner 4 bits
            // Column is formed by bits 1, 2, 3, 4
            int column = (sixBits[1] << 3) | (sixBits[2] << 2) |
                    (sixBits[3] << 1) | sixBits[4];

            // Step 4: Look up value in the S-box table
            int sBoxValue = Constants.sBoxes[sBoxIndex][row][column];

            // Step 5: Convert the 4-bit value to bit array and store in output
            // The value (0-15) is converted to 4 bits, MSB first
            for (int bitIndex = 0; bitIndex < 4; bitIndex++) {
                output[sBoxIndex * 4 + bitIndex] = (sBoxValue >> (3 - bitIndex)) & 1;
            }
        }
        return output;
    }

    /**
     * Adds PKCS#7 padding to the input data to make it a multiple of the block size.
     * <p>
     * PKCS#7 padding works by appending N bytes, where each byte has the value N,
     * and N is the number of bytes needed to reach the next block boundary.
     * If the input is already a multiple of the block size, a full block of padding
     * is added to ensure unambiguous padding removal during decryption.
     * <p>
     * <b>Why Full Block Padding is Necessary:</b><br>
     * Always adding padding (even when data is block-aligned) prevents ambiguity.
     * Without this, the decryptor cannot distinguish between actual data that
     * happens to end with valid padding bytes and real padding that should be removed.
     * <p>
     * <b>Examples (block size = 8):</b>
     * <ul>
     *   <li>Input: "HELLO" (5 bytes) → Output: "HELLO" + [03 03 03] (8 bytes)
     *       <br>Padding needed: 8 - (5 % 8) = 3 bytes</li>
     *   <li>Input: "HELLO!!!" (8 bytes) → Output: "HELLO!!!" + [08 08 08 08 08 08 08 08] (16 bytes)
     *       <br>Padding needed: 8 - (8 % 8) = 8 bytes (full block)</li>
     *   <li>Input: "HI" (2 bytes) → Output: "HI" + [06 06 06 06 06 06] (8 bytes)
     *       <br>Padding needed: 8 - (2 % 8) = 6 bytes</li>
     *   <li>Input: "" (0 bytes) → Output: [08 08 08 08 08 08 08 08] (8 bytes)
     *       <br>Padding needed: 8 - (0 % 8) = 8 bytes</li>
     * </ul>
     * <p>
     * <b>The padding ensures that:</b>
     * <ol>
     *   <li>The output length is always a multiple of the block size</li>
     *   <li>The padding can be unambiguously identified and removed after decryption</li>
     *   <li>The original data can be perfectly reconstructed, even if it ends with
     *       bytes that look like valid padding (e.g., "Hello\x03\x03\x03")</li>
     * </ol>
     * <p>
     * <b>Algorithm:</b>
     * <pre>
     * paddingLength = blockSize - (inputLength % blockSize)
     * output = input + [paddingLength] × paddingLength
     * </pre>
     *
     * @param input     the original data to be padded
     * @param blockSize the cipher block size in bytes (8 for DES)
     * @return a new byte array containing the input data followed by PKCS#7 padding bytes
     * @throws IllegalArgumentException if blockSize is less than 1 or greater than 255
     * @see #removePKCS7Padding(byte[])
     * @see <a href="https://tools.ietf.org/html/rfc5652#section-6.3">RFC 5652 - PKCS#7 Padding</a>
     */
    private byte[] addPKCS7Padding(byte[] input, int blockSize) {
        // Calculate how many padding bytes are needed
        // If input.length % blockSize == 0, we add a full block
        int paddingLength = blockSize - (input.length % blockSize);

        // Create new array with room for original data + padding
        byte[] padded = new byte[input.length + paddingLength];

        // Copy original data to the beginning of the new array
        System.arraycopy(input, 0, padded, 0, input.length);

        // Add padding bytes, each with value equal to the padding length
        // This makes the padding self-describing
        for (int i = input.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength;
        }

        return padded;
    }

    /**
     * Removes PKCS#7 padding from decrypted data.
     * <p>
     * This method validates and removes PKCS#7 padding to recover the original
     * plaintext. Validation is critical for security and data integrity - invalid
     * padding usually indicates either data corruption or use of an incorrect
     * decryption key.
     * <p>
     * <b>Validation and removal process:</b>
     * <ol>
     *   <li>Read the value N of the last byte</li>
     *   <li>Verify that 1 ≤ N ≤ data length</li>
     *   <li>Verify that the last N bytes all have the value N</li>
     *   <li>If validation passes, remove the last N bytes</li>
     *   <li>If validation fails, throw an exception</li>
     * </ol>
     * <p>
     * <b>Why validation is critical:</b>
     * <ul>
     *   <li>Prevents incorrect data truncation</li>
     *   <li>Detects corrupted ciphertext</li>
     *   <li>Detects wrong decryption key</li>
     *   <li>Ensures the padding was properly applied during encryption</li>
     *   <li>Protects against certain padding oracle attacks</li>
     * </ul>
     * <p>
     * <b>Example validation process (block size = 8):</b>
     * <pre>
     * Input:  [48 45 4C 4C 4F 03 03 03] = "HELLO" + padding
     * Step 1: Last byte = 03, so expect 3 padding bytes
     * Step 2: 1 ≤ 3 ≤ 8 ✓ (valid range)
     * Step 3: Last 3 bytes = [03 03 03] ✓ (all match)
     * Step 4: Remove last 3 bytes
     * Output: [48 45 4C 4C 4F] = "HELLO"
     * </pre>
     * <p>
     * <b>Invalid padding examples (would throw RuntimeException):</b>
     * <ul>
     *   <li><b>[48 45 4C 4C 4F 03 03 04]</b>
     *       <br>Last byte says 04, but not all last 4 bytes are 04
     *       <br>Error: "Invalid padding bytes"</li>
     *   <li><b>[48 45 4C 4C 4F 03 02 01]</b>
     *       <br>Last byte says 01, but should be at least 03
     *       <br>Error: "Invalid padding bytes"</li>
     *   <li><b>[48 45]</b> with last byte = 09
     *       <br>Last byte says remove 9 bytes, but only 2 bytes exist
     *       <br>Error: "Invalid padding length"</li>
     *   <li><b>[]</b> (empty array)
     *       <br>Error: "Cannot remove padding from empty data"</li>
     * </ul>
     * <p>
     * <b>The & 0xFF operation:</b><br>
     * Java bytes are signed (-128 to 127), but padding values are unsigned (0-255).
     * The bitwise AND with 0xFF converts a signed byte to its unsigned integer
     * equivalent: -1 becomes 255, -2 becomes 254, etc.
     * <p>
     * <b>Algorithm:</b>
     * <pre>
     * paddingLength = lastByte (as unsigned value)
     * validate: 1 ≤ paddingLength ≤ dataLength
     * validate: all last paddingLength bytes equal paddingLength
     * output = first (dataLength - paddingLength) bytes
     * </pre>
     *
     * @param input the padded data from which to remove PKCS#7 padding
     * @return a new byte array containing the original data without padding
     * @throws RuntimeException if the input is empty
     * @throws RuntimeException if the padding length is invalid
     *                          (less than 1 or greater than input length)
     * @throws RuntimeException if the padding bytes are not all equal to the
     *                          padding length (indicates corrupted data, wrong
     *                          decryption key, or tampering)
     * @see #addPKCS7Padding(byte[], int)
     * @see <a href="https://tools.ietf.org/html/rfc5652#section-6.3">RFC 5652 - PKCS#7 Padding</a>
     */
    private byte[] removePKCS7Padding(byte[] input) {
        // Validate that input is not empty
        if (input.length == 0) {
            throw new RuntimeException("Cannot remove padding from empty data");
        }

        // Read the last byte to determine how many padding bytes to remove
        // & 0xFF converts signed byte (-128 to 127) to unsigned int (0 to 255)
        int paddingLength = input[input.length - 1] & 0xFF;

        // Validate that padding length is reasonable
        // It must be at least 1 (minimum padding) and at most the data length
        if (paddingLength < 1 || paddingLength > input.length) {
            throw new RuntimeException("Invalid padding length: " + paddingLength +
                    " (data length: " + input.length + ")");
        }

        // Validate that all padding bytes have the correct value
        // This ensures the padding is valid and not corrupted
        for (int i = input.length - paddingLength; i < input.length; i++) {
            if ((input[i] & 0xFF) != paddingLength) {
                throw new RuntimeException("Invalid padding bytes at position " + i +
                        ": expected " + paddingLength +
                        ", found " + (input[i] & 0xFF));
            }
        }

        // Create new array without the padding bytes
        byte[] unpadded = new byte[input.length - paddingLength];
        System.arraycopy(input, 0, unpadded, 0, unpadded.length);

        return unpadded;
    }

    /**
     * Gets the Initialization Vector (IV) used for CBC mode.
     * <p>
     * The IV is required for decryption and should be transmitted along with
     * the ciphertext. It does not need to be kept secret but must be authentic
     * (not tampered with).
     *
     * @return the IV as a bit array (64 bits), or null if not yet generated
     * @see #setIvBits(int[])
     */
    public int[] getIvBits() {
        return ivBits;
    }

    /**
     * Sets the Initialization Vector (IV) for CBC mode decryption.
     * <p>
     * This method must be called before {@link #decrypt()} to provide the IV
     * that was used during encryption. The IV should be the same value that
     * was obtained from {@link #getIvBits()} after encryption.
     * <p>
     * <b>Important:</b> The IV must match the one used during encryption,
     * otherwise decryption will produce incorrect plaintext.
     *
     * @param ivBits the IV as a bit array (must be exactly 64 bits)
     * @throws IllegalArgumentException if ivBits is null or not 64 bits long
     * @see #getIvBits()
     */
    public void setIvBits(int[] ivBits) {
        if (ivBits == null) {
            throw new IllegalArgumentException("IV cannot be null");
        }
        if (ivBits.length != 64) {
            throw new IllegalArgumentException("IV must be exactly 64 bits, got " + ivBits.length);
        }
        this.ivBits = ivBits;
    }
}