import java.nio.file.Path;
import java.nio.file.Files;

class FileIndexer {
    Path directory;
    void checkDirectory() {
        if(Files.exists(directory)) {
            IO.print("Path exists ");
            if(Files.isDirectory(directory)) {
                IO.println("and is a directory.");
            } else if(Files.isRegularFile(directory)){
                IO.println("but is a regular file.");
            } else {
                IO.println("but is neither a regular file nor a directory.");
            }
        } else {
            IO.println("Path does not exist");
        }
    }
    FileIndexer(Path directory) {
        this.directory = directory;
    }
}
