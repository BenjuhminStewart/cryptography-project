import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class Hash {

    public static void main(String[] args) {
        String inputPath = System.getProperty("user.dir") + "/input/";

        File path = new File(args[0]);
        File key = new File(path + "/" + args[1]);
        File data = new File(path + "/" + args[2]);
        File custom = new File(path + "/" + args[3]);

        int len = 512;
        try {
            byte[] key_bytes = parseFile(key);
            byte[] data_bytes = parseFile(data);
            byte[] custom_bytes = parseFile(custom);

            byte[] out = hashKMACXOF(key_bytes, data_bytes, len, custom_bytes);
            KECCAK.print_bytes_hex(out);
        } catch (Exception e) {
            System.out.println("invalid input");
        }
    }

    public static byte[] hashCSHAKE(File data, int L, File function, File custom) throws IOException {
        byte[] X = Files.readAllBytes(data.toPath());
        byte[] N = Files.readAllBytes(function.toPath());
        byte[] S = Files.readAllBytes(custom.toPath());
        return KECCAK.CSHAKE256(X, L, N, S);
    }

    public static byte[] hashKMACXOF(byte[] K, byte[] X, int L, byte[] S) throws IOException {
        return KECCAK.KMACXOF256(K, X, L, S);
    }

    public static void write(File file, byte[] data) throws IOException {
        Files.write(file.toPath(), data);
    }

    /**
     * https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
     */
    public static byte[] parseFile(File file) throws IOException {
        String str = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8).replace(" ", "").trim();
        int len = str.length();

        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        }

        return data;
    }

}