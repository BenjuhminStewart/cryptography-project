import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class Hash {

    public static void main(String[] args) {
        String inputPath = System.getProperty("user.dir") + "/input/";
        File key = new File(inputPath + "key.txt");
        File data = new File(inputPath + "data.txt");
        File custom = new File(inputPath + "custom.txt");

        int len = 512;

        try {
            byte[] out = hashKMAC(key, data, len, custom);
            KECCAK.print_bytes_hex(out);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] hashCSHAKE(File data, int L, File function, File custom) throws IOException {
        byte[] X = Files.readAllBytes(data.toPath());
        byte[] N = Files.readAllBytes(function.toPath());
        byte[] S = Files.readAllBytes(custom.toPath());
        return KECCAK.CSHAKE256(X, L, N, S);
    }

    public static byte[] hashKMAC(File key, File data, int L, File custom) throws IOException {
        byte[] K = Files.readAllBytes(key.toPath());
        byte[] X = Files.readAllBytes(data.toPath());
        byte[] S = Files.readAllBytes(custom.toPath());
        return KECCAK.KMACXOF256(K, X, L, S);
    }

    public static void write(File file, byte[] data) throws IOException {
        Files.write(file.toPath(), data);
    }

}