package services;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import services.kmac.KECCAK;
import services.kmac.KMAC;

/**
 * Authentication tag services.
 */
public class AuthenticationTag implements IService {

    // auth file-location "passphrase"
    private final String name = "auth";
    private final String service = "Computes an authentication tag (MAC) of a given file under a given passphrase.";

    public void parse(String[] cmds) {
        if (cmds.length != 3) {
            help();
            return;
        }
        execute(cmds);
    }

    public void execute(String[] cmds) {
        try {
            final String GREEN = "\033[0;32m";
            final String CYAN = "\033[0;36m";
            final String RESET = "\033[0m";

            // get file to create tag for and convert to bytes
            File file = new File(cmds[1]);
            byte[] m = Files.readAllBytes(file.toPath());

            // get passphrase and convert to
            byte[] pw = cmds[2].getBytes();

            // compute tag and write to dest
            byte[] tag = computeAuthTag(m, pw);

            // get dest file location and write data to it
            String dest = getDefaultDestination(cmds[1], "authtag");
            File out = new File(dest);

            write(out, tag);
            System.out.println(
                    "\nSuccessfully created auth tag!\n " + CYAN + "--- src:  " + cmds[1].replace("\\", "/") + GREEN
                            + "\n --- dest: "
                            + dest + RESET);
        } catch (IOException e) {
            help();
        }
    }

    /**
     * Computes an authentication tag (MAC) of a given file under a given
     * passphrase.
     *
     * @param m  the file to compute the authentication tag for
     * @param pw the password used to create the authentication tag
     * @return authentication tag (MAC) of the give file under the given password
     */
    public byte[] computeAuthTag(byte[] m, byte[] pw) {
        return KECCAK.KMACXOF256(pw, m, KMAC.KMACXOF256_LENGTH, "T".getBytes());
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
                + " usage: auth [file-path] [passphrase]"
                + "\n\n");
        // Example 1
        sb.append(
                mainColor
                        + separator + RED + " Example:\n" + reset + separator
                        + " auth C:/Users/Benjamin/Documents/message.txt 1234\n\n" + separator
                        + " an authentication tag is automatically generated in the same root folder as the message with the name \"[message_name]-auth.txt\"\n");
        // Reset Console Color
        sb.append(reset);
        System.out.println(sb.toString());
    }

    public String getDescription() {
        return service;
    }
}