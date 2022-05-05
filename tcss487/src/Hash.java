import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.util.ArrayList;
import java.util.Scanner;

public class Hash {

    public static ArrayList<String> commands = new ArrayList<String>();

    public static final int KMACXOF256_LENGTH = 512;

    public static void main(String[] args) {

        buildCommands();
        System.out.println("Type \"help\" for more information");
        Scanner scan = new Scanner(System.in);
        while (true) {
            String input = "";
            System.out.print(">>> ");
            try {
                input = scan.nextLine().trim();
                if (input.equals("exit"))
                    break;
            } catch (Exception e) {
                break;
            }

            execute(input);
        }

        scan.close();
    }

    public static void buildCommands() {
        commands.add("kmac");
        commands.add("help");
    }

    public static void printHelp(String code) {

        // Colors (found from: https://www.w3schools.blog/ansi-colors-java)
        String separator = "      ";
        String mainColor = "\033[0;37m";
        String commandColor = "\u001B[33m";
        String reset = "\u001B[0m";

        if (code.equals("kmac")) {
            StringBuilder sb = new StringBuilder();
            // Header
            sb.append(commandColor + "\n      [kmac]\n\n");
            // Example 1
            sb.append(
                    mainColor
                            + "----- Example 1:\n" + separator
                            + "crypt > kmac C:/Users/Benjamin/Documents/message.txt\n\n" + separator
                            + "In the scenario of two arguments, the file is automatically encrypted in the same root folder as the message with the name\n"
                            + separator
                            + "[message_name]-plainhash.txt\n\n");
            // Example 2
            sb.append(
                    "----- Example 2:\n" + separator
                            + "kmac C:/Users/Benjamin/Documents/message.txt C:/Users/Benjamin/Encryptions/message-plainhash.txt\n\n"
                            + separator
                            + "In the scenario of 3 arguments, you can explicitly set the location of the message to be encrypted as well as the location of the output\n"
                            + separator
                            + "encyption along with its name");
            // Reset Console Color
            sb.append(reset);
            System.out.println(sb.toString());
        }

    }

    public static String getCommands() {
        return commands.toString();
    }

    public static void execute(String input) {
        // get commands
        String[] args = input.split(" ");

        if (args.length == 0)
            return;

        // arg length = 1, options left are help
        if (args.length == 1 && (args[0].equals("help") || args[0].equals("kmac"))) {
            printHelp("kmac");
        } else {
            String errorColor = "\033[0;31m";
            String reset = "\u001B[0m";
            System.out.println("\n" + errorColor + "'" + args[0] + "' is not a supported command");
            System.out.println(reset + " supported commands: " + getCommands() + "\n");
            return;
        }

        // arg length = 2, options are plain hash
        if (args.length == 2) {
            String command = args[0];
            if (command.equals("kmac")) {
                try {
                    String src = args[1];
                    String inputName = src.replace("\\", "/").substring(src.lastIndexOf("/"),
                            src.lastIndexOf("."));
                    String dest = src.replace("\\", "/").substring(0,
                            src.lastIndexOf("/"))
                            + inputName + "-" + "plainhash.txt";
                    plainCryptographicHash(src, dest);
                } catch (Exception e) {
                    printHelp("kmac");
                }

            } else {
                System.out.println("Unrecognized command, use command \"help\" for usage instructions");
            }
        }

        // arg length = 3, options are plain hash, authentication tag
        else if (args.length == 3) {

            String command = args[0];
            if (command.equals("kmac")) {
                String messageLocation = args[1];
                String outputLocation = args[2];
                plainCryptographicHash(messageLocation, outputLocation);
            }

        } else {
            // error
            System.out.println("");
        }
    }

    public static void plainCryptographicHash(String messageLocation, String encryptionLocation) {
        try {
            File loc = new File(messageLocation);
            File dest = new File(encryptionLocation);

            byte[] message = Files.readAllBytes(loc.toPath());
            byte[] output = hashKMACXOF256(message);
            write(dest, output);
            System.out.println("\nSuccesfully Hashed Message to \"" + encryptionLocation + "\"\n");

        } catch (NoSuchFileException e) {
            System.out.print("invalid input file");
        } catch (IOException e) {
            e.printStackTrace();
            System.out.print("invalid command");
            return;
        }
    }

    /**
     * Takes a message and computes a plain cryptography hash of byte arr M
     * 
     * @param M byte array of message to hash
     * @return plain cryptographic hash of the given byte array M
     */
    public static byte[] hashKMACXOF256(byte[] M) {
        return KECCAK.KMACXOF256("".getBytes(), M, KMACXOF256_LENGTH, "D".getBytes());
    }

    public static void write(File file, byte[] data) throws IOException {
        Files.write(file.toPath(), data);
    }

    public static byte[] readFileBytes(File file) throws IOException {
        return Files.readAllBytes(file.toPath());
    }
}