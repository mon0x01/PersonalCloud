void main() {
    FileMetadata file1 = null;
    try {
        file1 = new FileMetadata("notes.txt", "/home/monil/notes.txt", -1024);
    } catch(IllegalArgumentException e) {
        IO.println(e.getMessage());
    }
    IO.println("Program continues...");
    if(file1 != null) {
        IO.println(file1.getFileName());
        IO.println(file1.getFilePath());
        IO.println(file1.getFileSize());
    }
}