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

        shake.print_bytes(shake.left_encode(0));
        shake.print_bytes(shake.right_encode(0));

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
    public byte[] cSHAKE256e(String X, int L, String N, String S) {
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
        for (int i = 1; i < bytes.length; i++) {
            bytes[i] = reverse_bits(x);     // read the first 8 bits of x and reverse them
            x = x >> 8;                     // shift to next byte
        }

        bytes[0] = reverse_bits(n);
        
        return bytes;
    }

    public void bytepad() {
    }

    public void encode_string() {
    }

    

    private void print_bytes(byte[] bytes) {
        for (byte b : bytes) {
            System.out.print(Integer.toBinaryString(b & 255 | 256).substring(1) + " ");
        }
        System.out.println();
    }

    private void print_byte(byte b) {
        System.out.println(Integer.toBinaryString(b & 255 | 256).substring(1) + " ");
    }

    private byte reverse_bits(int n) {
        return (byte) (Integer.reverse(n) >>> (Integer.SIZE - Byte.SIZE));
    }
    
}
