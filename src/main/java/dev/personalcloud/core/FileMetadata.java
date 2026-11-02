package dev.personalcloud.core;

import java.util.LinkedHashMap;
import java.util.Map;

/** Metadata only. This object never contains or loads the file's contents. */
public final class FileMetadata {
    private final String fileName;
    private final String filePath;
    private final long fileSize;
    private final String lastModified;

    public FileMetadata(String fileName, String filePath, long fileSize) {
        this(fileName, filePath, fileSize, "");
    }

    public FileMetadata(String fileName, String filePath, long fileSize, String lastModified) {
        FileValidator.fileSizeValid(fileSize);
        if (fileName == null || fileName.isBlank()) throw new IllegalArgumentException("File name is required.");
        if (filePath == null || filePath.isBlank()) throw new IllegalArgumentException("File path is required.");
        this.fileName = fileName;
        this.filePath = filePath;
        this.fileSize = fileSize;
        this.lastModified = lastModified == null ? "" : lastModified;
    }

    public String getFileName() { return fileName; }
    public String getFilePath() { return filePath; }
    public long getFileSize() { return fileSize; }
    public String getLastModified() { return lastModified; }

    public Map<String, Object> toMap() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", fileName);
        result.put("path", filePath);
        result.put("size", fileSize);
        result.put("modified", lastModified);
        return result;
    }
}
