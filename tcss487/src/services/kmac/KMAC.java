package services.kmac;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;

import services.IService;

public class KMAC implements IService {
    public static final int KMACXOF256_LENGTH = 512;

    private static final String name = "kmac";
    private static final String service = "Compute cryptographic hash";

    public void parse(String[] input) {
        if (input.length == 2) {
            defaultLocation(input);
        } else {
            // invalid
            help();
            return;
        }
    }

    public void doFunction(String code, String messageLocation, String outputLocation) {
        execute(messageLocation, outputLocation);
    }

    private void defaultLocation(String[] args) {
        try {
            String src = args[1];
            String dest = getDefaultDestination(args[1], "plainhash");
            execute(src, dest);
        } catch (Exception e) {
            help();
        }

    }

    public String getDescription() {
        return service;
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
                + " usage: kmac [file-path]" + "\n\n");
        // Example 1
        sb.append(
                mainColor
                        + separator + RED + " Example:\n" + reset + separator
                        + " kmac C:/Users/Benjamin/Documents/message.txt\n\n" + separator
                        + " the file is automatically encrypted in the same root folder as the message with the name \"[message_name]-plainhash.txt\"\n");
        // Reset Console Color
        sb.append(reset);
        System.out.println(sb.toString());
    }

    /**
     * Takes a message and computes a plain cryptography hash of byte arr M
     * 
     * @param M byte array of message to hash
     * @return plain cryptographic hash of the given byte array M
     */
    private byte[] hashKMACXOF256(byte[] M) {
        return KECCAK.KMACXOF256("".getBytes(), M, KMACXOF256_LENGTH, "D".getBytes());
    }

    private void execute(String messageLocation, String encryptionLocation) {
        try {
            File loc = new File(messageLocation);
            File dest = new File(encryptionLocation);

            byte[] message = Files.readAllBytes(loc.toPath());
            byte[] output = hashKMACXOF256(message);

            write(dest, output);
            System.out.println(
                    "\nSuccesfully Hashed Message to \"" + encryptionLocation + "\"\n" + "Using KMACXOF256 encryption");
        } catch (NoSuchFileException e) {
            System.out.print("\ninvalid input file\n");
        } catch (IOException e) {
            e.printStackTrace();
            System.out.print("\ninvalid command\n");
            return;
        }
    }
}
