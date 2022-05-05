/**
 * Implementation of the Keccak Core Algorithm.
 */
public class KECCAK {

    private static final long[] KECCAKF_RNDC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static final int[] KECCAKF_ROTC = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };

    private static final int[] KECCAKF_PILN = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };

    private static final int KECCAKF_ROUNDS = 24;

    private static final int SHAKE256_MDLEN = 32;

    private byte[] state;

    private int rate;
    private int pt;

    private KECCAK() {
    };

    /**
     * Initialize state, rate, and pt
     * 
     * @param mdlen the hash output (bytes)
     */
    private void sha3_init(int mdlen) {
        state = new byte[200];
        rate = 200 - 2 * mdlen;
        pt = 0;
    }

    /**
     * Call sha3_init with the hash output used for SHAKE256
     */
    private void shake256_init() {
        sha3_init(SHAKE256_MDLEN);
    }

    /**
     * keccak compression function
     * 
     * @param state the state array
     */
    private void sha3_keccakf(byte[] state) {

        long[] lanes = new long[25];
        long[] planes = new long[5];

        // map from bytes in 'state' to longs and store in 'lanes'
        for (int i = 0, j = 0; i < 25; i++, j += 8) {
            lanes[i] = (((long) state[j + 0] & 0xFFL) << 0) | (((long) state[j + 1] & 0xFFL) << 8) |
                    (((long) state[j + 2] & 0xFFL) << 16) | (((long) state[j + 3] & 0xFFL) << 24) |
                    (((long) state[j + 4] & 0xFFL) << 32) | (((long) state[j + 5] & 0xFFL) << 40) |
                    (((long) state[j + 6] & 0xFFL) << 48) | (((long) state[j + 7] & 0xFFL) << 56);
        }

        for (int r = 0; r < KECCAKF_ROUNDS; r++) {
            // theta mapping
            for (int i = 0; i < 5; i++)
                planes[i] = lanes[i] ^ lanes[i + 5] ^ lanes[i + 10] ^ lanes[i + 15] ^ lanes[i + 20];

            for (int i = 0; i < 5; i++) {
                long t = planes[(i + 4) % 5] ^ ROTL64(planes[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5)
                    lanes[j + i] ^= t;
            }

            // rho and pi mapping
            long t = lanes[1];
            for (int i = 0; i < 24; i++) {
                int j = KECCAKF_PILN[i];
                planes[0] = lanes[j];
                lanes[j] = ROTL64(t, KECCAKF_ROTC[i]);
                t = planes[0];
            }

            // chi mapping
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++)
                    planes[i] = lanes[j + i];
                for (int i = 0; i < 5; i++)
                    lanes[j + i] ^= (~planes[(i + 1) % 5]) & planes[(i + 2) % 5];
            }

            // iota mapping
            lanes[0] ^= KECCAKF_RNDC[r];
        }

        // map from longs in 'lanes' to bytes and store in 'state'
        for (int i = 0, j = 0; i < 25; i++, j += 8) {
            long t = lanes[i];
            for (int k = 0; k < Byte.SIZE; k++) {
                state[j + k] = (byte) ((t >> k * Byte.SIZE) & 0xFF);
            }
        }
    }

    /**
     * Update state with new data
     * 
     * @param data new data
     * @param len  length
     */
    private void sha3_update(byte[] data, int len) {
        int j = pt;
        for (int i = 0; i < len; i++) {
            state[j++] ^= data[i];
            if (j >= rate) {
                sha3_keccakf(state);
                j = 0;
            }
        }
        pt = j;
    }

    /**
     * Extensible Output Function
     */
    private void shake_xof() {
        // original = 0x1F
        state[pt] ^= 0x04;
        state[rate - 1] ^= 0x80;
        sha3_keccakf(state);
        pt = 0;
    }

    /**
     * Extensible Output Function
     */
    private void shake_out(byte[] out, int len) {
        int j = pt;
        for (int i = 0; i < len; i++) {
            if (j >= rate) {
                sha3_keccakf(state);
                j = 0;
            }
            out[i] = state[j++];
        }
        pt = j;
    }

    /**
     * Rotate 64-bit value to the left
     * 
     * @param x the 64-bit value to be shifted
     * @param y the value of positions to be shifted
     * @return x rotated to the left by y
     */
    private long ROTL64(long x, int y) {
        return (((x) << (y)) | ((x) >>> (64 - (y))));
    }

    /**
     * Encode Left
     * 
     * @param x the int value to be left encoded
     * @return the left encoded value, x
     */
    private static byte[] left_encode(int x) {
        int n = 1;
        while (1 << 8 * n <= x)
            n++;

        byte[] bytes = new byte[n + 1];
        for (int i = bytes.length - 1; i > 0; i--) {
            bytes[i] = (byte) x;
            x = x >> 8;
        }

        bytes[0] = (byte) n;

        return bytes;
    }

    /**
     * Encode Right
     * 
     * @param x the int value to be right encoded
     * @return the right encoded value, x
     */
    private static byte[] right_encode(int x) {
        int n = 1;
        while (1 << 8 * n <= x)
            n++;

        byte[] bytes = new byte[n + 1];
        for (int i = bytes.length - 2; i >= 0; i--) {
            bytes[i] = (byte) x;
            x = x >> 8;
        }

        bytes[bytes.length - 1] = (byte) n;

        return bytes;
    }

    /**
     * Encode string
     * 
     * @param s the string to be encoded
     * @return the encoded string, s
     */
    private static byte[] encode_string(byte[] s) {
        byte[] encoded = left_encode(s.length * 8);
        byte[] bytes = concat_arrays(encoded, s);

        return bytes;
    }

    /**
     * Given an encoding factor, bytepad given byte array
     * 
     * @param x byte array
     * @param w factor to encode by
     * @return the bytepadded byte array, x
     */
    private static byte[] bytepad(byte[] x, int w) {
        byte[] encoded = left_encode(w);
        byte[] z = concat_arrays(encoded, x);

        // no need for step 2 due to byte-oriented implementation

        while (z.length % w != 0) {
            z = concat_byte(z, (byte) 0);
        }

        return z;
    }

    /**
     * Concatenate given byte arrays
     * 
     * @param arr1 first array
     * @param arr2 second array
     * @return first array concatenated with second array (first || second)
     */
    private static byte[] concat_arrays(byte[] arr1, byte[] arr2) {
        byte[] bytes = new byte[arr1.length + arr2.length];

        System.arraycopy(arr1, 0, bytes, 0, arr1.length);
        System.arraycopy(arr2, 0, bytes, arr1.length, arr2.length);

        return bytes;
    }

    /**
     * Concatenate byte into byte array
     * 
     * @param arr array to concatenate byte with
     * @param b   byte to concatenate with array
     * @return byte concatenated with byte array
     */
    private static byte[] concat_byte(byte[] arr, byte b) {
        byte[] bytes = new byte[arr.length + 1];

        System.arraycopy(arr, 0, bytes, 0, arr.length);
        bytes[bytes.length - 1] = b;

        return bytes;
    }

    /**
     * Print the given byte array as a hex string
     * 
     * @param bytes the bytes to be printed
     */
    public static void print_bytes_hex(byte[] bytes) {
        System.out.println(bytes_to_hex(bytes));
    }

    public static String bytes_to_hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(Integer.toHexString(b & 255 | 256).substring(1) + " ");
        return sb.toString();
    }

    /**
     * hash input using cSHAKE256
     * 
     * @param X input to be hashed
     * @param L output length (bits)
     * @param N name
     * @param S custom string
     * @return the hashed string
     */
    public static byte[] CSHAKE256(byte[] X, int L, byte[] N, byte[] S) {
        byte[] bytes = new byte[L / 8];
        KECCAK k = new KECCAK();

        k.shake256_init();

        // KECCAK[512](bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L)
        byte[] arg = concat_arrays(bytepad(concat_arrays(encode_string(N), encode_string(S)), 136), X);
        k.sha3_update(arg, arg.length);

        k.shake_xof();
        k.shake_out(bytes, bytes.length);

        return bytes;
    }

    /**
     * Encrypt input using KMACXOF256
     * 
     * @param K MAC key
     * @param X input to be encrypted
     * @param L output length (bits)
     * @param S custom string
     * @return the MAC tag
     */
    public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        byte[] new_x = concat_arrays(concat_arrays(bytepad(encode_string(K), 136), X), right_encode(0));
        return CSHAKE256(new_x, L, "KMAC".getBytes(), S);
    }

    /**
     * Encrypt input using KMACXOF256
     * 
     * @param K MAC key
     * @param X input to be encrypted
     * @param L output length (bits)
     * @param S custom string
     * @return the MAC tag
     */
    public static byte[] KMAC256(byte[] K, byte[] X, int L, byte[] S) {
        byte[] new_x = concat_arrays(concat_arrays(bytepad(encode_string(K), 136), X), right_encode(L));
        return CSHAKE256(new_x, L, "KMAC".getBytes(), S);
    }
}
