class FileMetadata {
    private String fileName;
    private String filePath;
    private long fileSize;

    FileMetadata(String fileName, String filePath, long fileSize) {
        FileValidator.fileSizeValid(fileSize);
        this.fileName = fileName;
        this.filePath = filePath;
        this.fileSize = fileSize;
    }
    String getFileName() {
        return fileName;
    }
    String getFilePath() {
        return filePath;
    }
    long getFileSize() {
        return fileSize;
    }
}