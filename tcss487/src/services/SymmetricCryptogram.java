package services;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;

import services.kmac.KECCAK;

/**
 * Encrypt/Decrypt a file symmetrically using a passphrase.
 */
public class SymmetricCryptogram implements IService {

    private final String service = "Encrypt/Decrypt a file symmetrically using a passphrase.";
    public final String name = "symm";

    public void encrypt(String path, byte[] m, byte[] pw) {
        // store 512 bits / 64 bytes of random data
        SecureRandom rand = new SecureRandom();
        byte[] z = new byte[64];
        rand.nextBytes(z);

        // calc ke || ka and separate them
        byte[] ke_ka = KECCAK.KMACXOF256(KECCAK.concat_arrays(z, pw), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = Arrays.copyOfRange(ke_ka, 0, ke_ka.length / 2);
        byte[] ka = Arrays.copyOfRange(ke_ka, ke_ka.length / 2, ke_ka.length);

        // calc c and xor w/ m
        byte[] c = KECCAK.KMACXOF256(ke, "".getBytes(), m.length * 8, "SKE".getBytes());
        for (int i = 0; i < c.length; i++)
            c[i] ^= m[i];

        // calc t
        byte[] t = KECCAK.KMACXOF256(ka, m, 512, "SKA".getBytes());

        // combine z, c, t
        byte[] result = KECCAK.concat_arrays(z, c);
        result = KECCAK.concat_arrays(result, t);

        try {
            String dest = getDefaultDestination(path, "symm-encrypted");
            File file = new File(dest);
            write(file, result);
            printSuccessfulDecryption(dest);
        } catch (IOException e) {
            help();
        }
    }

    public void decrypt(String path, byte[] zct, byte[] pw) {
        int length = 64;
        byte[] z = Arrays.copyOfRange(zct, 0, length);
        byte[] c = Arrays.copyOfRange(zct, length, zct.length - length);
        byte[] t = Arrays.copyOfRange(zct, zct.length - length, zct.length);

        // calc ke || ka and separate them
        byte[] ke_ka = KECCAK.KMACXOF256(KECCAK.concat_arrays(z, pw), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = Arrays.copyOfRange(ke_ka, 0, ke_ka.length / 2);
        byte[] ka = Arrays.copyOfRange(ke_ka, ke_ka.length / 2, ke_ka.length);

        // calculate m
        byte[] m = KECCAK.KMACXOF256(ke, "".getBytes(), c.length * 8, "SKE".getBytes());
        for (int i = 0; i < m.length; i++)
            m[i] ^= c[i];

        byte[] t_prime = KECCAK.KMACXOF256(ka, m, 512, "SKA".getBytes());

        try {
            if (Arrays.equals(t, t_prime)) {
                String dest = getDefaultDestination(path, "symdec");
                File file = new File(dest);

                write(file, m);
                printSuccessfulEncryption(dest);
            } else {
                System.out.println("\nIncorrect password! \n");
                help();
            }
        } catch (IOException e) {
            help();
        }
    }

    public void printSuccessfulEncryption(String encryptionLocation) {
        System.out.println(
                "\nSuccesfully Encrypted Message to \"" + encryptionLocation + "\"\n"
                        + "Using Symmetric encryption w/ pw");
    }

    public void printSuccessfulDecryption(String encryptionLocation) {
        System.out.println(
                "\nSuccesfully Decrypted Message to \"" + encryptionLocation + "\"\n"
                        + "Using Symmetric decryption w/ pw");
    }

    public void help() {
        // Colors (found from: https://www.w3schools.blog/ansi-colors-java)
        final String separator = "      ";
        final String mainColor = "\033[0;37m";
        final String RED = "\033[0;31m";
        final String CYAN = "\033[0;36m";
        final String commandColor = "\u001B[33m";
        final String reset = "\u001B[0m";
        StringBuilder sb = new StringBuilder();
        // Header
        sb.append(commandColor + "\n" + name + mainColor + " - " + service + "\n\n" + separator + CYAN
                + " usage: symm ['-e' -> encrypt || '-d' -> decrypt] [file-path] [passphrase]" + "\n\n");
        // Example 1
        sb.append(
                mainColor
                        + separator + RED + " Example 1 [Encryption]:\n" + reset + separator
                        + " symm -e C:/Users/Benjamin/Documents/message.txt 1234\n\n" + separator
                        + " the file is automatically encrypted with passphrase '1234' as \"[message_name]-symm-encrypted.txt\"\n\n");
        sb.append(
                mainColor
                        + separator + RED + " Example 1 [Encryption]:\n" + reset + separator
                        + " symm -d C:/Users/Benjamin/Documents/message-symm-encrypted.txt 1234\n\n" + separator
                        + " the file is automatically decrypted using passphrase '1234' as \"[message_name]-symm-decrypted.txt\"\n");
        // Reset Console Color
        sb.append(reset);
        System.out.println(sb.toString());
    }

    public String getDescription() {
        return service;
    }

    @Override
    public void parse(String[] cmds) {
        if (cmds.length != 4) {
            help();
            return;
        }

        try {
            String type = cmds[1];

            String path = cmds[2];
            File file = new File(path);

            byte[] pw = cmds[3].getBytes();
            byte[] m = Files.readAllBytes(file.toPath());

            if (type.equals("encrypt") || type.equals("e") || type.equals("-e")) {
                encrypt(path, m, pw);
            } else if (type.equals("decrypt") || type.equals("d") || type.equals("-d")) {
                decrypt(path, m, pw);
            } else {
                help();
            }
        } catch (Exception e) {
            help();
        }

    }

}