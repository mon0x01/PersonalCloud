package dev.personalcloud.core;

public final class FileValidator {
    private FileValidator() {}

    public static void fileSizeValid(long fileSize) {
        if (fileSize < 0) throw new IllegalArgumentException("File size cannot be negative.");
    }
}
