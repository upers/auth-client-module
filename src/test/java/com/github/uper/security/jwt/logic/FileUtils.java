package com.github.uper.security.jwt.logic;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class FileUtils {

    public static String readFileFromClassPath(String fileName) throws IOException {
        File file = new File(FileUtils.class.getClassLoader().getResource(fileName).getFile());

        return new String(Files.readAllBytes(file.toPath()));
    }
}
