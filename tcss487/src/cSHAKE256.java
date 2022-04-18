import java.math.BigInteger;
import java.util.Arrays;

/**
 * Implementation of the 256 bit cSHAKE algorithm.
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 */
public class cSHAKE256 {

    private cSHAKE256() {};
    public static void main(String[] args) {
        cSHAKE256 shake = new cSHAKE256();

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
        if (x < 0 || x >= Math.pow(2, 2040)) 
            throw new IllegalArgumentException("x must satisfy the following condition: 0 <= x <= 2^2040");

        // 1. let n be the smallest positive integer for which 2^8n > x
        int n = 1;
        while (1 << 8 * n <= x)
            n++;

        // 2. let x_1, x_2, ... , x_n be the base-256 encoding of x satifying: 
        //                        x = sum(2^(8(n - i)) * x_i), for i = 1 -> n
        // 3. let O_i = enc_8(x_i), for i = 1 -> n
        byte[] bytes = BigInteger.valueOf(x).toByteArray();
        print_bytes(bytes);

        byte[] result = new byte[bytes.length + 1];
        for (int i = 0; i < bytes.length; i++) 
            result[i] = bytes[i];

        // 4. let O_(n + 1) = enc_8(n)
        result[bytes.length] = (byte) n;

        // 5. return O = O_1 || O_2 || ... || O_n || O_(n + 1)
        return result;
    }

    public void bytepad() {
    }

    public void encode_string() {
    }

    public void left_encode() {
    }

    private void print_bytes(byte[] bytes) {
        for (byte b : bytes) {
            System.out.print(Integer.toBinaryString(b & 255 | 256).substring(1) + " ");
        }
        System.out.println();
    }
    
}
