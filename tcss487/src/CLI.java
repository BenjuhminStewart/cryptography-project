import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.util.HashMap;
import java.util.Scanner;

public class CLI {

    private static final int KMACXOF256_LENGTH = 512;
    private static HashMap<String, String> commands = new HashMap<String, String>();

    public CLI() {
        buildCommands();
    }

    public void runApplication() {
        System.out.println("Type \"help\" for more information or \"exit\" to exit the program");
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

    private void buildCommands() {
        commands.put("kmac", "Compute cryptographic hash");
        commands.put("auth", "Compute authentication tag");
        commands.put("symmetric", "Encrypt symmetric under passphrase");
        commands.put("dsc", "Decrypt symmetric cryptogram under passphrase");
        commands.put("gen-schnorr", "Generate Schnorr key pair from passphrase");
        commands.put("schnorr", "Encrypt byte[] under Schnorr public key");
        commands.put("dc", "Decrypt a cryptogram under passphrase");
        commands.put("gensig", "Generate signature for byte[] under passphrase");
        commands.put("versig", "Verify a signature for byte[] under Schnorr public key");

        // Help
        commands.put("help", "Get commands");

        // Exit
        commands.put("exit", "Exit application");
    }

    private static String getCommands() {
        return commands.keySet().toString();
    }

    public static void invalidCode(String code) {
        String errorColor = "\033[0;31m";
        String reset = "\u001B[0m";
        System.out.println("\n" + errorColor + "'" + code + "' is not a supported command");
        System.out.println(reset + " supported commands: " + getCommands() + "\n");
    }

    public static void kmacHelp() {
        // Colors (found from: https://www.w3schools.blog/ansi-colors-java)
        String separator = "      ";
        String mainColor = "\033[0;37m";
        String commandColor = "\u001B[33m";
        String reset = "\u001B[0m";
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

    public static void getCommandInfo() {
        String commandColor = "\u001B[33m";
        String reset = "\u001B[0m";
        System.out.println("\nsupported commands: " + getCommands() + "\n");
        for (int i = 0; i < commands.size(); i++) {
            String command = commands.keySet().toArray()[i].toString();
            System.out.printf("--- %s[%s]%s - \"%s\"\n", commandColor, command, reset, commands.get(command));
        }
        System.out.println();
    }

    public static void unsupportedFunctions(String code) {
        // Colors (found from: https://www.w3schools.blog/ansi-colors-java)
        String errorColor = "\033[0;31m";
        String warningColor = "\033[0;90m";
        String reset = "\u001B[0m";
        System.out.printf("\n%s*%s[%s]%s: \"%s\" (%s*Non-Functional%s)\n\n", warningColor, errorColor, code, reset,
                commands.get(code), warningColor, reset);
    }

    public static void printHelp(String code) {

        if (code.equals("kmac")) {
            kmacHelp();
        } else if (code.equals("help")) {
            getCommandInfo();
        } else if (!commands.containsKey(code)) {
            invalidCode(code);
        } else {
            unsupportedFunctions(code);
        }
    }

    public static void execute(String input) {
        // get commands
        String[] args = input.split(" ");

        if (args.length == 0)
            return;

        if (args.length == 1) {
            printHelp(args[0]);
        } else if (args.length == 2) {
            twoArgs(args);
        } else if (args.length == 3) {
            threeArgs(args);
        } else {
            System.out.println("Too many commands");
        }

    }

    public static void twoArgs(String[] args) {
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
                    printHelp(args[0]);
                }

            } else {
                printHelp(args[0]);
            }
        }
    }

    public static void threeArgs(String[] args) {
        String command = args[0];
        String messageLocation = args[1];
        String outputLocation = args[2];
        doFunction(command, messageLocation, outputLocation);

    }

    public static void doFunction(String code, String messageLocation, String outputLocation) {
        if (code.equals("kmac")) {
            plainCryptographicHash(messageLocation, outputLocation);
        } else {
            printHelp(code);
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
