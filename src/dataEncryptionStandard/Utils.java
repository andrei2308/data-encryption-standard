package dataEncryptionStandard;

/**
 * Utility methods for DES algorithm implementation.
 *
 * @author Chitoiu Andrei
 */
public class Utils {

    /**
     * Converts a byte array to a bit array (int array with 0s and 1s)
     *
     * @param bytes the input byte array
     * @return bit array where each element is 0 or 1
     */
    public static int[] bytesToBits(byte[] bytes) {
        int[] bits = new int[bytes.length * 8];
        int index = 0;
        for (byte b : bytes) {
            for (int i = 7; i >= 0; i--) {
                bits[index++] = (b >> i) & 1;
            }
        }
        return bits;
    }

    /**
     * Converts a bit array (int array with 0s and 1s) to a byte array
     *
     * @param bits the input bit array
     * @return byte array
     */
    public static byte[] bitsToBytes(int[] bits) {
        byte[] bytes = new byte[bits.length / 8];
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                bytes[i] = (byte) ((bytes[i] << 1) | bits[i * 8 + j]);
            }
        }
        return bytes;
    }

    /**
     * Converts a hexadecimal string to a byte array
     *
     * @param hex the hexadecimal string (e.g., "133457799BBCDFF1")
     * @return byte array
     * @throws IllegalArgumentException if hex string is invalid
     */
    public static byte[] hexStringToBytes(String hex) {
        // Remove any spaces or special characters
        hex = hex.replaceAll("[^0-9A-Fa-f]", "");

        // Check if valid length
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int index = i * 2;
            bytes[i] = (byte) Integer.parseInt(hex.substring(index, index + 2), 16);
        }
        return bytes;
    }

    /**
     * Converts a byte array to a hexadecimal string
     *
     * @param bytes the byte array
     * @return hexadecimal string
     */
    public static String bytesToHexString(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

    /**
     * Splits a bit array into two equal halves
     *
     * @param bits the input bit array
     * @return array containing [leftHalf, rightHalf]
     */
    public static int[][] split(int[] bits) {
        int mid = bits.length / 2;
        int[] left = new int[mid];
        int[] right = new int[mid];

        System.arraycopy(bits, 0, left, 0, mid);
        System.arraycopy(bits, mid, right, 0, mid);

        return new int[][]{left, right};
    }

    /**
     * Combines two bit arrays into one
     *
     * @param left  the left bit array
     * @param right the right bit array
     * @return combined bit array
     */
    public static int[] combine(int[] left, int[] right) {
        int[] combined = new int[left.length + right.length];
        System.arraycopy(left, 0, combined, 0, left.length);
        System.arraycopy(right, 0, combined, left.length, right.length);
        return combined;
    }

    /**
     * Performs XOR operation on two bit arrays
     *
     * @param a first bit array
     * @param b second bit array
     * @return XOR result
     */
    public static int[] xor(int[] a, int[] b) {
        int[] result = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    /**
     * Performs circular left shift on a bit array
     *
     * @param bits      the input bit array
     * @param numShifts number of positions to shift left
     * @return shifted bit array
     */
    public static int[] leftShift(int[] bits, int numShifts) {
        int[] shifted = new int[bits.length];
        for (int i = 0; i < bits.length; i++) {
            shifted[i] = bits[(i + numShifts) % bits.length];
        }
        return shifted;
    }

    /**
     * Applies a permutation table to input bits
     *
     * @param input the input bit array (each element is 0 or 1)
     * @param table the permutation table (1-indexed positions)
     * @return the permuted bit array
     */
    public static int[] permute(int[] input, Integer[] table) {
        int[] permuted = new int[table.length];
        for (int i = 0; i < table.length; i++) {
            permuted[i] = input[table[i] - 1];
        }
        return permuted;
    }
}