import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Scanner;

import services.AuthenticationTag;
import services.IService;
import services.SymmetricCryptogram;
import services.EllipticCurve;
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
        commands.put("ec", new EllipticCurve());
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
            int commandLength = command.length();
            int spacing = 4 - commandLength;
            String spacingStr = "";
            for (int i = 0; i < spacing; i++)
                spacingStr += " ";

            System.out.printf("--- %s[%s]%s %s- \"%s\"\n", commandColor, command, reset, spacingStr,
                    commands.get(command).getDescription());

        }
        System.out.printf("--- %s[%s]%s - \"%s\"\n", commandColor, "help", reset, "List all commands");
        System.out.printf("--- %s[%s]%s - \"%s\"\n", commandColor, "exit", reset, "Exit the program");
        System.out.println();
    }

    public static byte[] readFileBytes(File file) throws IOException {
        return Files.readAllBytes(file.toPath());
    }
}
