package dataEncryptionStandard;

import static dataEncryptionStandard.Utils.*;

/**
 * Implementation of the Data Encryption Standard (DES) algorithm.
 * DES is a symmetric-key block cipher that encrypts 64-bit blocks of data
 * using a 56-bit key through 16 rounds of Feistel network operations.
 *
 * @author Chitoiu Andrei
 */
public class DES {
    /** The plaintext or ciphertext data to be processed */
    private final byte[] plainText;

    /** The 64-bit encryption/decryption key (with 8 parity bits) */
    private final byte[] key;

    /**
     * Constructs a DES cipher instance with the given plaintext/ciphertext and key.
     *
     * @param plainText the input data to be encrypted or decrypted
     * @param key the 64-bit key (16 hex characters) used for encryption/decryption
     */
    public DES(byte[] plainText, byte[] key) {
        this.plainText = plainText;
        this.key = key;
    }

    /**
     * Encrypts the plaintext using the DES algorithm.
     *
     * Process:
     * @1. Apply initial permutation (IP) to the plaintext
     * @2. Generate 16 round keys from the master key
     * @3. Split permuted plaintext into left and right halves (32 bits each)
     * @4. Apply 16 rounds of Feistel encryption
     * @5. Swap and combine the final left and right halves
     * @6. Apply final permutation (FP)
     * @7. Convert result to hexadecimal string
     *
     * @return the encrypted ciphertext as a hexadecimal string
     */
    public String encrypt() {

        // prepare args
        int[] keyBits = bytesToBits(key);
        int[] plainTextBits = bytesToBits(plainText);

        // step 1: initial permutation on plain text
        int[] permutedPlainText = permute(plainTextBits, Constants.initialPermutationTable);

        // step 2: generate round keys
        int[][] roundKeys = generateRoundKeys(keyBits);

        // step 3: split plaintext into 2 halves
        int[][] LR = split(permutedPlainText);
        int[] left = LR[0];
        int[] right = LR[1];

        // step 4: apply 16 rounds of Feistel encryption
        for (int round = 0; round < 16; round++) {
            int[] newRight = xor(left, feistel(right, roundKeys[round]));
            left = right;
            right = newRight;
        }

        // step 5: combine right and left swapped
        int[] combined = combine(right, left);

        // step 6: apply final permutation
        int[] cipherBits = permute(combined, Constants.finalPermutation);

        // step 7: convert to bytes and then to hex string
        byte[] cipherBytes = bitsToBytes(cipherBits);

        return bytesToHexString(cipherBytes);
    }

    /**
     * Decrypts the ciphertext using the DES algorithm.
     *
     * DES decryption is identical to encryption except the round keys
     * are applied in reverse order (round 15 to round 0).
     *
     * Process:
     * @1. Apply initial permutation (IP) to the ciphertext
     * @2. Generate 16 round keys from the master key
     * @3. Split permuted ciphertext into left and right halves
     * @4. Apply 16 rounds of Feistel decryption with reversed keys
     * @5. Swap and combine the final left and right halves
     * @6. Apply final permutation (FP)
     * @7. Convert result back to ASCII string
     *
     * @return the decrypted plaintext as an ASCII string
     */
    public String decrypt() {

        // step 1: convert key and ciphertext to bits
        int[] keyBits = bytesToBits(key);
        int[] cipherTextBits = bytesToBits(plainText); // reusing plainText field for ciphertext

        // step 2: apply initial permutation
        int[] permutedCipherText = permute(cipherTextBits, Constants.initialPermutationTable);

        // step 3: generate round keys
        int[][] roundKeys = generateRoundKeys(keyBits);

        // step 4: split into left and right halves
        int[][] LR = split(permutedCipherText);
        int[] left = LR[0];
        int[] right = LR[1];

        // step 5: apply the 16 rounds with reversed keys
        for (int round = 15; round >= 0; round--) {
            int[] newRight = xor(left, feistel(right, roundKeys[round]));
            left = right;
            right = newRight;
        }

        // step 6: combine right and left swapped
        int[] combined = combine(right, left);

        // step 7: apply final permutation
        int[] plainBits = permute(combined, Constants.finalPermutation);
        byte[] plainBytes = bitsToBytes(plainBits);

        return new String(plainBytes);
    }

    /**
     * Generates the 16 round keys from the master key.
     *
     * Process:
     * @1. Apply Permuted Choice 1 (PC-1) to reduce 64-bit key to 56 bits
     * @2. Split into two 28-bit halves (C and D)
     * @3. For each of 16 rounds:
     *    @- Perform circular left shift on both halves (1 or 2 positions)
     *    @- Combine the shifted halves
     *    @- Apply Permuted Choice 2 (PC-2) to get 48-bit round key
     *
     * @param keyBits the 64-bit master key as a bit array
     * @return array of 16 round keys, each 48 bits long
     */
    private int[][] generateRoundKeys(int[] keyBits) {
        // step 1: permute the key using PC-1
        int[] permutedKey = permute(keyBits, Constants.permutedChoice1);

        // step 2: split the key into C and D halves
        int[][] CD = split(permutedKey);
        int[] C = CD[0];
        int[] D = CD[1];

        int[][] roundKeys = new int[16][];

        // step 3: generate 16 round keys
        for (int round = 0; round < 16; round++) {
            // perform circular left shift
            C = leftShift(C, Constants.circularLeftShiftRounds[round]);
            D = leftShift(D, Constants.circularLeftShiftRounds[round]);

            // combine C and D
            int[] CD_combined = combine(C, D);

            // apply PC-2 to get 48-bit round key
            roundKeys[round] = permute(CD_combined, Constants.permutedChoice2);
        }

        return roundKeys;
    }

    /**
     * The Feistel function (F-function) - the core of each DES round.
     *
     * Process:
     * @1. Expand right half from 32 bits to 48 bits using expansion table
     * @2. XOR the expanded right half with the round key
     * @3. Apply 8 S-boxes to substitute and reduce from 48 bits to 32 bits
     * @4. Apply P-box permutation to the S-box output
     *
     * @param right the 32-bit right half of the data block
     * @param roundKey the 48-bit round key for this round
     * @return 32-bit output after all transformations
     */
    private int[] feistel(int[] right, int[] roundKey) {

        // step 1: expand right part from 32 to 48 bits
        int[] expanded = permute(right, Constants.expansionTable);

        // step 2: XOR with round key
        int[] xored = xor(expanded, roundKey);

        // step 3: apply s-boxes (48 bits -> 32 bits)
        int[] sBoxOutput = applySBoxes(xored);

        // step 4: apply p-box permutation
        return permute(sBoxOutput, Constants.straightPermutationTable);
    }

    /**
     * Applies the 8 S-boxes to convert 48 bits to 32 bits through substitution.
     *
     * Each S-box:
     * - Takes 6 bits as input
     * - Uses outer 2 bits (first and last) to select row (0-3)
     * - Uses inner 4 bits to select column (0-15)
     * - Outputs 4 bits based on the S-box lookup table
     *
     * Process:
     * @1. Split 48-bit input into 8 groups of 6 bits
     * @2. For each 6-bit group:
     *    @- Extract row number from bits 0 and 5
     *    @- Extract column number from bits 1-4
     *    @- Look up value in corresponding S-box
     *    @- Convert 4-bit value to bit array
     * @3. Concatenate all 8 outputs to form 32-bit result
     *
     * @param input 48-bit input as 8 groups of 6 bits
     * @return 32-bit output as 8 groups of 4 bits
     */
    private int[] applySBoxes(int[] input) {
        int[] output = new int[32];

        // process each of the 8 S-boxes
        for (int i = 0; i < 8; i++) {

            // step 1: extract 6 bits from the input
            int[] sixBits = new int[6];
            System.arraycopy(input, i * 6, sixBits, 0, 6);

            // step 2: extract the outer bits (first and last) for the row
            int row = (sixBits[0] << 1) | sixBits[5];

            // step 3: extract the inner 4 bits for the column
            int col = (sixBits[1] << 3) | (sixBits[2] << 2) | (sixBits[3] << 1) | sixBits[4];

            // step 4: look up value in S-box
            int sBoxValue = Constants.sBoxes[i][row][col];

            // step 5: convert 4-bit value to bit array and store in output
            for (int j = 0; j < 4; j++) {
                output[i * 4 + j] = (sBoxValue >> (3 - j)) & 1;
            }
        }
        return output;
    }

}