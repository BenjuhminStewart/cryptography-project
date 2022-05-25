package services;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public abstract interface IService {
    public void help();

    public String getDescription();

    public void parse(String[] cmds);

    default void write(File file, byte[] data) throws IOException {
        Files.write(file.toPath(), data);
    }

    default String getDefaultDestination(String src, String ext) {
        String name = src.replace("\\", "/");
        name = name.substring(name.lastIndexOf("/"), name.lastIndexOf("."));
        String dest = src.replace("\\", "/");
        dest = dest.substring(0, dest.lastIndexOf("/")) + name + "-" + ext + ".txt";
        return dest;
    }
}
