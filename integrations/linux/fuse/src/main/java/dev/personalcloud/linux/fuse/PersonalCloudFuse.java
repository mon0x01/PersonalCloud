package dev.personalcloud.linux.fuse;

import dev.personalcloud.storage.ReadOnlyVirtualFilesystem;
import dev.personalcloud.storage.ReferenceFileSystemModel;
import ru.serce.jnrfuse.ErrorCodes;
import ru.serce.jnrfuse.FuseFillDir;
import ru.serce.jnrfuse.FuseStubFS;
import ru.serce.jnrfuse.struct.FileStat;
import ru.serce.jnrfuse.struct.FuseBufvec;
import ru.serce.jnrfuse.struct.FuseFileInfo;
import ru.serce.jnrfuse.struct.Timespec;
import jnr.ffi.Pointer;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Linux FUSE2 adapter for the read-only PersonalCloud virtual namespace. */
public final class PersonalCloudFuse extends FuseStubFS {
    private static final long MAX_READ = ReadOnlyVirtualFilesystem.MAX_READ_BYTES;
    private static final long FILE_MODE = FileStat.S_IFREG | FileStat.S_IRUSR;
    private static final long DIRECTORY_MODE = FileStat.S_IFDIR | FileStat.S_IRUSR | FileStat.S_IXUSR;
    private static final long USER_ID = unixId("uid");
    private static final long GROUP_ID = unixId("gid");

    private final ReadOnlyVirtualFilesystem filesystem;

    public PersonalCloudFuse(ReferenceFileSystemModel model) {
        this.filesystem = new ReadOnlyVirtualFilesystem(model);
    }

    @Override public String getFSName() { return "PersonalCloud"; }

    @Override public int getattr(String path, FileStat stat) {
        try {
            var attributes = filesystem.attributes(path);
            boolean directory = attributes.directory();
            stat.st_mode.set(directory ? DIRECTORY_MODE : FILE_MODE);
            stat.st_nlink.set(directory ? 2 : 1);
            stat.st_uid.set(USER_ID);
            stat.st_gid.set(GROUP_ID);
            stat.st_size.set(directory ? 0 : attributes.sizeBytes());
            stat.st_blksize.set(128 * 1024);
            stat.st_blocks.set(directory ? 0 : (attributes.sizeBytes() + 511) / 512);
            long modified = epochSeconds(attributes.modifiedAt());
            stat.st_atim.tv_sec.set(modified);
            stat.st_mtim.tv_sec.set(modified);
            stat.st_ctim.tv_sec.set(modified);
            return 0;
        } catch (NoSuchFileException missing) {
            return -ErrorCodes.ENOENT();
        } catch (IOException failure) {
            return -ErrorCodes.EIO();
        }
    }

    @Override public int readdir(String path, Pointer buffer, FuseFillDir filter, long offset, FuseFileInfo info) {
        try {
            List<String> entries = new ArrayList<>();
            entries.add(".");
            entries.add("..");
            entries.addAll(filesystem.list(path));
            if (offset < 0 || offset > entries.size()) return -ErrorCodes.EINVAL();
            for (int index = (int) offset; index < entries.size(); index++) {
                if (filter.apply(buffer, entries.get(index), (FileStat) null, index + 1L) != 0) break;
            }
            return 0;
        } catch (NoSuchFileException missing) {
            return -ErrorCodes.ENOENT();
        } catch (IOException failure) {
            return -ErrorCodes.EIO();
        }
    }

    @Override public int opendir(String path, FuseFileInfo info) {
        try {
            filesystem.list(path);
            return 0;
        } catch (NoSuchFileException missing) {
            return -ErrorCodes.ENOENT();
        } catch (IOException failure) {
            return -ErrorCodes.ENOTDIR();
        }
    }

    @Override public int open(String path, FuseFileInfo info) {
        long flags = info.flags.get();
        if ((flags & 3L) != 0L) return -ErrorCodes.EROFS(); // O_ACCMODE: anything except O_RDONLY
        try {
            filesystem.openForRead(path);
            return 0;
        } catch (NoSuchFileException missing) {
            return -ErrorCodes.ENOENT();
        } catch (IOException failure) {
            if (failure.getMessage() != null && failure.getMessage().contains("directory")) return -ErrorCodes.EISDIR();
            if (failure.getMessage() != null && failure.getMessage().contains("offline")) return -ErrorCodes.EHOSTUNREACH();
            return -ErrorCodes.EIO();
        }
    }

    @Override public int read(String path, Pointer buffer, long size, long offset, FuseFileInfo info) {
        if (offset < 0 || size < 0 || size > MAX_READ) return -ErrorCodes.EINVAL();
        if (size == 0) return 0;
        try {
            byte[] bytes = filesystem.read(path, offset, (int) size);
            buffer.put(0, bytes, 0, bytes.length);
            return bytes.length;
        } catch (NoSuchFileException missing) {
            return -ErrorCodes.ENOENT();
        } catch (IOException failure) {
            if (failure.getMessage() != null && failure.getMessage().contains("offline")) return -ErrorCodes.EHOSTUNREACH();
            return -ErrorCodes.EIO();
        } catch (IllegalArgumentException invalid) {
            return -ErrorCodes.EINVAL();
        }
    }

    @Override public int access(String path, int mask) {
        if ((mask & 2) != 0) return -ErrorCodes.EROFS(); // W_OK
        try {
            ReferenceFileSystemModel.Attributes attributes = filesystem.attributes(path);
            if ((mask & 1) != 0 && !attributes.directory()) return -ErrorCodes.EACCES(); // X_OK on regular files
            return 0;
        } catch (NoSuchFileException missing) {
            return -ErrorCodes.ENOENT();
        } catch (IOException failure) {
            return -ErrorCodes.EIO();
        }
    }

    @Override public int release(String path, FuseFileInfo info) { return 0; }
    @Override public int releasedir(String path, FuseFileInfo info) { return 0; }

    // Explicitly reject every data/metadata mutation callback. This is a hard read-only boundary,
    // not merely an invitation for clients to avoid sending writes.
    @Override public int write(String path, Pointer buffer, long size, long offset, FuseFileInfo info) { return -ErrorCodes.EROFS(); }
    @Override public int write_buf(String path, FuseBufvec buffer, long offset, FuseFileInfo info) { return -ErrorCodes.EROFS(); }
    @Override public int create(String path, long mode, FuseFileInfo info) { return -ErrorCodes.EROFS(); }
    @Override public int mknod(String path, long mode, long device) { return -ErrorCodes.EROFS(); }
    @Override public int mkdir(String path, long mode) { return -ErrorCodes.EROFS(); }
    @Override public int unlink(String path) { return -ErrorCodes.EROFS(); }
    @Override public int rmdir(String path) { return -ErrorCodes.EROFS(); }
    @Override public int rename(String oldPath, String newPath) { return -ErrorCodes.EROFS(); }
    @Override public int link(String oldPath, String newPath) { return -ErrorCodes.EROFS(); }
    @Override public int symlink(String target, String linkPath) { return -ErrorCodes.EROFS(); }
    @Override public int truncate(String path, long size) { return -ErrorCodes.EROFS(); }
    @Override public int ftruncate(String path, long size, FuseFileInfo info) { return -ErrorCodes.EROFS(); }
    @Override public int chmod(String path, long mode) { return -ErrorCodes.EROFS(); }
    @Override public int chown(String path, long uid, long gid) { return -ErrorCodes.EROFS(); }
    @Override public int utimens(String path, Timespec[] timespec) { return -ErrorCodes.EROFS(); }
    @Override public int setxattr(String path, String name, Pointer value, long size, int flags) { return -ErrorCodes.EROFS(); }
    @Override public int removexattr(String path, String name) { return -ErrorCodes.EROFS(); }
    @Override public int fallocate(String path, int mode, long offset, long length, FuseFileInfo info) { return -ErrorCodes.EROFS(); }

    private static long epochSeconds(String value) {
        if (value == null || value.isBlank()) return 0;
        try { return Instant.parse(value).getEpochSecond(); }
        catch (RuntimeException ignored) { return 0; }
    }

    private static long unixId(String attribute) {
        try { return ((Number) java.nio.file.Files.getAttribute(java.nio.file.Path.of("/proc/self"), "unix:" + attribute)).longValue(); }
        catch (Exception failure) { throw new IllegalStateException("PersonalCloud FUSE requires Linux /proc unix identity attributes.", failure); }
    }
}
