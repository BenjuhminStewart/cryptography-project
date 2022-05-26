import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.util.HashMap;
import java.util.Scanner;

import services.AuthenticationTag;
import services.IService;
import services.SymmetricCryptogram;
import services.kmac.KMAC;

public class CLI {

    private static HashMap<String, IService> commands = new HashMap<String, IService>();

    public CLI() {
        buildCommands();
    }

    public void runApplication() {
        System.out.println("Type \"help\" for more information or \"exit\" to exit the program");
        Scanner scan = new Scanner(System.in);
        while (true) {
            String[] input;
            System.out.print(">>> ");
            try {
                input = scan.nextLine().trim().split(" ");
                if (input.length == 0)
                    continue;

                if (input[0].equals("exit")) {
                    break;
                } else if (input[0].equals("help")) {
                    help();
                } else if (commands.containsKey(input[0])) {
                    commands.get(input[0]).parse(input);
                } else {
                    invalidCode(input[0]);
                }
            } catch (Exception e) {
                break;
            }
        }

        scan.close();
    }

    private void buildCommands() {
        commands.put("kmac", new KMAC());
        commands.put("auth", new AuthenticationTag());
        commands.put("symm", new SymmetricCryptogram());
        // commands.put("dsc", "Decrypt symmetric cryptogram under passphrase");
        // commands.put("gen-schnorr", "Generate Schnorr key pair from passphrase");
        // commands.put("schnorr", "Encrypt byte[] under Schnorr public key");
        // commands.put("dc", "Decrypt a cryptogram under passphrase");
        // commands.put("gensig", "Generate signature for byte[] under passphrase");
        // commands.put("versig", "Verify a signature for byte[] under Schnorr public
        // key");
    }

    private static String getCommands() {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (String command : commands.keySet()) {
            sb.append(command + ", ");
        }
        sb.append("help, exit]");
        return sb.toString();
    }

    public static void invalidCode(String code) {
        String errorColor = "\033[0;31m";
        String reset = "\u001B[0m";
        System.out.println("\n" + errorColor + "'" + code + "' is not a supported command");
        System.out.println(reset + " supported commands: " + getCommands() + "\n");
    }

    public static void help() {
        String commandColor = "\u001B[33m";
        String reset = "\u001B[0m";
        System.out.println("\nsupported commands: " + getCommands() + "\n");
        for (String command : commands.keySet()) {
            System.out.printf("--- %s[%s]%s - \"%s\"\n", commandColor, command, reset,
                    commands.get(command).getDescription());
        }
        System.out.printf("--- %s[%s]%s - \"%s\"\n", commandColor, "help", reset, "List all command");
        System.out.printf("--- %s[%s]%s - \"%s\"\n", commandColor, "exit", reset, "Exit the program");
        System.out.println();
    }

    // public static void twoArgs(String[] args) {
    // // arg length = 2, options are plain hash
    // if (args.length == 2) {
    // String command = args[0];
    // if (command.equals("kmac")) {
    // try {
    // String src = args[1];
    // String inputName = src.replace("\\", "/").substring(src.lastIndexOf("/"),
    // src.lastIndexOf("."));
    // String dest = src.replace("\\", "/").substring(0,
    // src.lastIndexOf("/"))
    // + inputName + "-" + "plainhash.txt";
    // plainCryptographicHash(src, dest);
    // } catch (Exception e) {
    // printHelp(args[0]);
    // }

    // } else {
    // printHelp(args[0]);
    // }
    // }
    // }

    // public static void threeArgs(String[] args) {
    // String command = args[0];
    // String messageLocation = args[1];
    // String outputLocation = args[2];
    // doFunction(command, messageLocation, outputLocation);
    // }

    // public static void doFunction(String code, String messageLocation, String
    // outputLocation) {
    // if (code.equals("kmac")) {
    // plainCryptographicHash(messageLocation, outputLocation);
    // } else {
    // printHelp(code);
    // }
    // }

    public static byte[] readFileBytes(File file) throws IOException {
        return Files.readAllBytes(file.toPath());
    }
}
