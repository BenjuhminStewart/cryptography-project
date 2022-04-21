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
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    private static final int[] KECCAKF_PILN = {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    private static final int KECCAKF_ROUNDS = 24;

    private static final int SHAKE256_MDLEN = 32;

    private byte[] b;

    private int rsiz;
    private int pt;

    private KECCAK() { };

    private void sha3_init(int mdlen) {
        b = new byte[200];
        rsiz = 200 - 2 * mdlen;
        pt = 0;
    }

    private void shake256_init() {
        sha3_init(SHAKE256_MDLEN);
    }

    private void sha3_keccakf(byte[] b) {

        long[] q = new long[25];
        long[] bc = new long[5];

        // map from bytes in 'b' to longs and store in 'q'
        for (int i = 0, j = 0; i < 25; i++, j += 8) {
            q[i] = (((long) b[j + 0] & 0xFFL) << 0)  | (((long) b[j + 1] & 0xFFL) << 8)  |
                   (((long) b[j + 2] & 0xFFL) << 16) | (((long) b[j + 3] & 0xFFL) << 24) |
                   (((long) b[j + 4] & 0xFFL) << 32) | (((long) b[j + 5] & 0xFFL) << 40) |
                   (((long) b[j + 6] & 0xFFL) << 48) | (((long) b[j + 7] & 0xFFL) << 56);
        }

        for (int r = 0; r < KECCAKF_ROUNDS; r++) {

            // theta 
            for (int i = 0; i < 5; i++)
                bc[i] = q[i] ^ q[i + 5] ^ q[i + 10] ^ q[i + 15] ^ q[i + 20];

            for (int i = 0; i < 5; i++) {
                long t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5)
                    q[j + i] ^= t;
            }

            // rho pi
            long t = q[1];
            for (int i = 0; i < 24; i++) {
                int j = KECCAKF_PILN[i];
                bc[0] = q[j];
                q[j] = ROTL64(t, KECCAKF_ROTC[i]);
                t = bc[0];
            }

            //  chi
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) 
                    bc[i] = q[j + i];
                for (int i = 0; i < 5; i++) 
                    q[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }

            //  iota
            q[0] ^= KECCAKF_RNDC[r];
        }

        // map from longs in 'q' to bytes and store in 'b'
        for (int i = 0, j = 0; i < 25; i++, j += 8) {
            long t = q[i];
            for (int k = 0; k < Byte.SIZE; k++) {
                b[j + k] = (byte) ((t >> k * Byte.SIZE) & 0xFF);
            }
        }
    }

    private void sha3_update(byte[] data, int len) {
        int j = pt;
        for (int i = 0; i < len; i++) {
            b[j++] ^= data[i];
            if (j >= rsiz) {
                sha3_keccakf(b);
                j = 0;
            }
        }
        pt = j;
    }
    
    private void shake_xof() {
        // original = 0x1F
        b[pt] ^= 0x04;
        b[rsiz -1] ^= 0x80;
        sha3_keccakf(b);
        pt = 0;
    }

    private void shake_out(byte[] out, int len) {
        int j = pt;
        for (int i = 0; i < len; i++) {
            if (j >= rsiz) {
                sha3_keccakf(b);
                j = 0;
            }
            out[i] = b[j++];
        }
        pt = j;
    } 

    private long ROTL64(long x, int y) {
        return (((x) << (y)) | ((x) >>> (64 - (y))));
    }

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

    private static byte[] encode_string(byte[] s) {
        byte[] encoded = left_encode(s.length * 8);
        byte[] bytes = concat_arrays(encoded, s);

        return bytes;
    }

    private static byte[] bytepad(byte[] x, int w) {
        byte[] encoded = left_encode(w);
        byte[] z = concat_arrays(encoded, x);

        // no need for step 2 due to byte-oriented implementation

        while (z.length % w != 0) {
            z = concat_byte(z, (byte) 0);
        }

        return z;
    }

    private static byte[] concat_arrays(byte[] arr1, byte[] arr2) {
        byte[] bytes = new byte[arr1.length + arr2.length];

        System.arraycopy(arr1, 0, bytes, 0, arr1.length);
        System.arraycopy(arr2, 0, bytes, arr1.length, arr2.length);

        return bytes;
    }

    private static byte[] concat_byte(byte[] arr, byte b) {
        byte[] bytes = new byte[arr.length + 1];

        System.arraycopy(arr, 0, bytes, 0, arr.length);
        bytes[bytes.length - 1] = b;

        return bytes;
    }

    public static void print_bytes_hex(byte[] bytes) {
        for (byte b : bytes) {
            System.out.print(Integer.toHexString(b & 255 | 256).substring(1) + " ");
        }
        System.out.println();
    }

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

    public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        byte[] new_x = concat_arrays(concat_arrays(bytepad(encode_string(K), 136), X), right_encode(L));
        return CSHAKE256(new_x, L, "KMAC".getBytes(), S);
    }

    public static void main(String[] args) {

        int L = 512;
        byte[] S = "My Tagged Application".getBytes();
        byte[] X = new byte[] {0, 1, 2, 3};
        byte[] K = new byte[] {64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
                               81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95};

        // key, data, length, cust string
        byte[] bytes = KMACXOF256(K, X, L, S);
        print_bytes_hex(bytes);
    }
}
