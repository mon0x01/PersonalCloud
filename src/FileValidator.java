class FileValidator {
    static void fileSizeValid(long fileSize) {
        if(fileSize < 0)
            throw new IllegalArgumentException("File size cannot be negative");
    }
}