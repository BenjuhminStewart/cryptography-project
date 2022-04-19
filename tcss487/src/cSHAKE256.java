import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Implementation of the 256 bit cSHAKE algorithm.
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 */
public class cSHAKE256 {

    private cSHAKE256() {};
    public static void main(String[] args) {
        cSHAKE256 shake = new cSHAKE256();

        // byte[] bytes = shake.left_encode(0);
        // shake.print_bytes_binary(bytes);

        byte[] encoded_n = shake.encode_string("".getBytes());
        byte[] encoded_s = shake.encode_string("Email Signature".getBytes());

        shake.print_bytes_hex(encoded_n);
        shake.print_bytes_hex(encoded_s);

        byte[] combined = shake.concat_arrays(encoded_n, encoded_s);
        byte[] bytepad = shake.bytepad(combined, 168);

        shake.print_bytes_hex(bytepad);

    }

    /**
     * Implementation of the cSHAKE 256 bit encryption algorithm. Supports only
     * input strings and output lengths that are whole bytes, and otherwise results
     * in an error.
     * @param X The main input bit string. May be of any length, including zero.
     * @param L Integer representing the requested output length in bits.
     * @param N Function-name bit string. Set to an empty string if no function
     *          other than cSHAKE is desired.
     * @param S Customization bit string, defining a variant of the function. 
     *          Set to an empty string if no customization is desired.
     * @return  
     */
    public byte[] SHAKE256(String x, int l, String n, String s) {
        return null;
    }

    public byte[] right_encode(int x) {
        if (x < 0 || x >= 1 << 2040) 
            throw new IllegalArgumentException("x must satisfy the following condition: 0 <= x <= 2^2040");

        int n = 1;
        while (1 << 8 * n <= x)
            n++;
        
        byte[] bytes = new byte[n + 1];
        for (int i = 0; i < bytes.length - 1; i++) {
            bytes[i] = reverse_bits(x);     // read the first 8 bits of x and reverse them
            x = x >> 8;                     // shift to next byte
        }

        bytes[n] = reverse_bits(n);
        
        return bytes;
    }

    public byte[] left_encode(int x) {
        if (x < 0 || x >= 1 << 2040) 
            throw new IllegalArgumentException("x must satisfy the following condition: 0 <= x <= 2^2040");

        int n = 1;
        while (1 << 8 * n <= x)
            n++;

        byte[] bytes = new byte[n + 1];
        for (int i = bytes.length - 1; i > 0; i--) {
            bytes[i] = (byte) x;            // read the first 8 bits of x and reverse them
            x = x >> 8;                     // shift to next byte
        }

        bytes[0] = (byte) n;

        return bytes;
    }

    public byte[] encode_string(byte[] s) {
        byte[] encoded = left_encode(s.length * 8);
        byte[] bytes = concat_arrays(encoded, s);

        return bytes;
    }

    public byte[] bytepad(byte[] x, int w) {
        byte[] encoded = left_encode(w);
        byte[] z = concat_arrays(encoded, x);

        // step 2 of bytepad excluded due to redundancy?
        while (z.length % w != 0) {
            z = concat_byte(z, (byte) 0);
        }

        return z;
    }
    
    private byte reverse_bits(int n) {
        return (byte) (Integer.reverse(n) >>> (Integer.SIZE - Byte.SIZE));
    }

    private byte[] concat_arrays(byte[] arr1, byte[] arr2) {
        byte[] bytes = new byte[arr1.length + arr2.length];

        System.arraycopy(arr1, 0, bytes, 0, arr1.length);
        System.arraycopy(arr2, 0, bytes, arr1.length, arr2.length);

        return bytes;
    }

    private byte[] concat_byte(byte[] arr, byte b) {
        byte[] bytes = new byte[arr.length + 1];

        System.arraycopy(arr, 0, bytes, 0, arr.length);
        bytes[bytes.length - 1] = b;

        return bytes;
    }

    private void print_bytes_binary(byte[] bytes) {
        for (byte b : bytes) {
            System.out.print(Integer.toBinaryString(b & 255 | 256).substring(1) + " ");
        }
        System.out.println();
    }

    private void print_byte_binary(byte b) {
        System.out.println(Integer.toBinaryString(b & 255 | 256).substring(1) + " ");
    }

    private void print_bytes_hex(byte[] bytes) {
        for (byte b : bytes) {
            System.out.print(Integer.toHexString(b & 255 | 256).substring(1) + " ");
        }
        System.out.println();
    }

    private void print_byte_hex(byte b) {
        System.out.println(Integer.toHexString(b & 255 | 256).substring(1) + " ");
    }
    
}
