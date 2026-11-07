package dev.personalcloud.linux.fuse;

import dev.personalcloud.storage.ReadOnlyVirtualFilesystem;
import dev.personalcloud.storage.ReferenceFileSystemModel;
import dev.personalcloud.storage.WritableVirtualFilesystem;
import ru.serce.jnrfuse.ErrorCodes;
import ru.serce.jnrfuse.FuseFillDir;
import ru.serce.jnrfuse.FuseStubFS;
import ru.serce.jnrfuse.struct.FileStat;
import ru.serce.jnrfuse.struct.FuseFileInfo;
import ru.serce.jnrfuse.struct.Timespec;
import jnr.ffi.Pointer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Linux FUSE adapter for the PersonalCloud namespace.
 *
 * <p>The reference planes remain read-only. Eligible storage under
 * {@code /Devices/<device>/Filesystem} is writable through the owning peer's
 * authenticated protocol. Writes are staged locally and published only after a
 * complete, integrity-verified upload, so an interrupted write never corrupts the
 * original remote file.</p>
 */
public final class PersonalCloudFuse extends FuseStubFS {
    private static final long MAX_READ = ReadOnlyVirtualFilesystem.MAX_READ_BYTES;
    private static final long FILE_MODE = FileStat.S_IFREG | FileStat.S_IRUSR | FileStat.S_IWUSR;
    private static final long DIRECTORY_MODE = FileStat.S_IFDIR | FileStat.S_IRUSR | FileStat.S_IWUSR | FileStat.S_IXUSR;
    private static final long USER_ID = unixId("uid");
    private static final long GROUP_ID = unixId("gid");
    private static final long O_ACCMODE = 3L;
    private static final long O_RDONLY = 0L;
    private static final long O_CREAT = 0100L;
    private static final long O_EXCL = 0200L;
    private static final long O_TRUNC = 01000L;
    private static final long O_APPEND = 02000L;

    private final WritableVirtualFilesystem filesystem;
    private final ConcurrentHashMap<Long, WriteHandle> handles = new ConcurrentHashMap<>();
    private final AtomicLong nextHandle = new AtomicLong(1);

    public PersonalCloudFuse(ReferenceFileSystemModel model, dev.personalcloud.control.LocalControlClient client) {
        if (model == null || client == null) {
            throw new IllegalArgumentException("A reference filesystem model and control client are required.");
        }
        this.filesystem = new WritableVirtualFilesystem(model, client);
    }

    public PersonalCloudFuse(WritableVirtualFilesystem filesystem) {
        if (filesystem == null) throw new IllegalArgumentException("A filesystem is required.");
        this.filesystem = filesystem;
    }

    @Override public String getFSName() { return "PersonalCloud"; }

    @Override public int getattr(String path, FileStat stat) {
        try {
            var attributes = filesystem.attributes(path);
            boolean directory = attributes.directory();
            long size = directory ? 0 : attributes.sizeBytes();
            String modified = attributes.modifiedAt();
            WriteHandle open = openHandle(path);
            if (open != null && !directory) {
                try {
                    size = Files.size(open.staging);
                    modified = Instant.ofEpochMilli(Files.getLastModifiedTime(open.staging).toMillis()).toString();
                } catch (IOException ignored) { }
            }
            stat.st_mode.set(directory ? DIRECTORY_MODE : FILE_MODE);
            stat.st_nlink.set(directory ? 2 : 1);
            stat.st_uid.set(USER_ID);
            stat.st_gid.set(GROUP_ID);
            stat.st_size.set(size);
            stat.st_blksize.set(128 * 1024);
            stat.st_blocks.set(directory ? 0 : (size + 511) / 512);
            long modifiedSeconds = epochSeconds(modified);
            stat.st_atim.tv_sec.set(modifiedSeconds);
            stat.st_mtim.tv_sec.set(modifiedSeconds);
            stat.st_ctim.tv_sec.set(modifiedSeconds);
            return 0;
        } catch (NoSuchFileException missing) {
            return -ErrorCodes.ENOENT();
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
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
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int opendir(String path, FuseFileInfo info) {
        try {
            filesystem.list(path);
            return 0;
        } catch (NoSuchFileException missing) {
            return -ErrorCodes.ENOENT();
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int open(String path, FuseFileInfo info) {
        long flags = info.flags.get();
        long access = flags & O_ACCMODE;
        if (access == O_RDONLY) {
            try {
                filesystem.openForRead(path);
                return 0;
            } catch (NoSuchFileException missing) {
                return -ErrorCodes.ENOENT();
            } catch (IOException | RuntimeException failure) {
                return errno(failure);
            }
        }
        if (!filesystem.isWritable(path)) return -ErrorCodes.EROFS();
        try {
            boolean exists = filesystem.exists(path);
            ReferenceFileSystemModel.Attributes attributes = exists ? filesystem.attributes(path) : null;
            if (!exists && (flags & O_CREAT) == 0) return -ErrorCodes.ENOENT();
            if (exists && (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0) return -ErrorCodes.EEXIST();
            if (attributes != null && attributes.directory()) return -ErrorCodes.EISDIR();
            Path staging = filesystem.createStaging();
            if (exists && (flags & O_TRUNC) == 0) {
                filesystem.download(path, staging);
            } else {
                Files.createFile(staging);
                if (!exists) filesystem.upload(path, staging, false);
            }
            long fh = nextHandle.getAndIncrement();
            info.fh.set(fh);
            WriteHandle handle = new WriteHandle(path, staging, exists, (flags & O_APPEND) != 0);
            // O_TRUNC must publish the empty staging even when the caller writes no bytes.
            if (exists && (flags & O_TRUNC) != 0) handle.dirty = true;
            handles.put(fh, handle);
            return 0;
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int create(String path, long mode, FuseFileInfo info) {
        if (!filesystem.isWritable(path)) return -ErrorCodes.EROFS();
        try {
            Path staging = filesystem.createStaging();
            Files.createFile(staging);
            filesystem.upload(path, staging, false);
            long fh = nextHandle.getAndIncrement();
            info.fh.set(fh);
            handles.put(fh, new WriteHandle(path, staging, false, false));
            return 0;
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int read(String path, Pointer buffer, long size, long offset, FuseFileInfo info) {
        if (offset < 0 || size < 0 || size > MAX_READ) return -ErrorCodes.EINVAL();
        if (size == 0) return 0;
        WriteHandle handle = handle(info);
        if (handle != null) {
            try (FileChannel channel = FileChannel.open(handle.staging, StandardOpenOption.READ)) {
                long fileSize = channel.size();
                if (offset >= fileSize) return 0;
                int requested = (int) Math.min(size, fileSize - offset);
                ByteBuffer bytes = ByteBuffer.allocate(requested);
                channel.position(offset);
                int total = 0;
                while (bytes.hasRemaining()) {
                    int read = channel.read(bytes);
                    if (read < 0) break;
                    total += read;
                }
                if (total > 0) buffer.put(0, bytes.array(), 0, total);
                return total;
            } catch (IOException | RuntimeException failure) {
                return errno(failure);
            }
        }
        try {
            byte[] bytes = filesystem.read(path, offset, (int) size);
            buffer.put(0, bytes, 0, bytes.length);
            return bytes.length;
        } catch (NoSuchFileException missing) {
            return -ErrorCodes.ENOENT();
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int write(String path, Pointer buffer, long size, long offset, FuseFileInfo info) {
        if (size < 0 || size > Integer.MAX_VALUE) return -ErrorCodes.EINVAL();
        if (size == 0) return 0;
        WriteHandle handle = handle(info);
        if (handle == null) return -ErrorCodes.EBADF();
        try {
            byte[] bytes = new byte[(int) size];
            buffer.get(0, bytes, 0, (int) size);
            try (FileChannel channel = FileChannel.open(handle.staging, StandardOpenOption.WRITE)) {
                long position = handle.append ? channel.size() : offset;
                if (position < 0) return -ErrorCodes.EINVAL();
                channel.position(position);
                ByteBuffer source = ByteBuffer.wrap(bytes);
                while (source.hasRemaining()) channel.write(source);
            }
            handle.dirty = true;
            return (int) size;
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int flush(String path, FuseFileInfo info) {
        WriteHandle handle = handle(info);
        return handle == null ? 0 : publish(handle);
    }

    @Override public int fsync(String path, int datasync, FuseFileInfo info) {
        return flush(path, info);
    }

    @Override public int release(String path, FuseFileInfo info) {
        WriteHandle handle = handles.remove(info.fh.get());
        if (handle == null) return 0;
        int result = publish(handle);
        filesystem.deleteStaging(handle.staging);
        return result;
    }

    @Override public int truncate(String path, long size) {
        if (size < 0) return -ErrorCodes.EINVAL();
        if (!filesystem.isWritable(path)) return -ErrorCodes.EROFS();
        WriteHandle open = openHandle(path);
        if (open != null) {
            try {
                truncateFile(open.staging, size);
                open.dirty = true;
                return 0;
            } catch (IOException | RuntimeException failure) {
                return errno(failure);
            }
        }
        try {
            if (!filesystem.exists(path)) return -ErrorCodes.ENOENT();
            Path staging = filesystem.createStaging();
            try {
                filesystem.download(path, staging);
                truncateFile(staging, size);
                filesystem.upload(path, staging, true);
            } finally {
                filesystem.deleteStaging(staging);
            }
            return 0;
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int ftruncate(String path, long size, FuseFileInfo info) {
        if (size < 0) return -ErrorCodes.EINVAL();
        WriteHandle handle = handle(info);
        if (handle == null) return truncate(path, size);
        try {
            truncateFile(handle.staging, size);
            handle.dirty = true;
            return 0;
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int mkdir(String path, long mode) {
        if (!filesystem.isWritable(path)) return -ErrorCodes.EROFS();
        try {
            filesystem.createDirectory(path);
            return 0;
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int unlink(String path) {
        if (!filesystem.isWritable(path)) return -ErrorCodes.EROFS();
        try {
            filesystem.delete(path, false);
            return 0;
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int rmdir(String path) {
        if (!filesystem.isWritable(path)) return -ErrorCodes.EROFS();
        try {
            filesystem.delete(path, false);
            return 0;
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int rename(String oldPath, String newPath) {
        if (!filesystem.isWritable(oldPath) || !filesystem.isWritable(newPath)) return -ErrorCodes.EROFS();
        try {
            filesystem.move(oldPath, newPath);
            return 0;
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int utimens(String path, Timespec[] timespec) {
        if (!filesystem.isWritable(path)) return -ErrorCodes.EROFS();
        // Timestamps are owned by the source device; the remote protocol does not
        // expose arbitrary timestamp mutation. Report success rather than pretending
        // the remote file's metadata was changed.
        return 0;
    }

    @Override public int chmod(String path, long mode) {
        return filesystem.isWritable(path) ? -ErrorCodes.EPERM() : -ErrorCodes.EROFS();
    }

    @Override public int chown(String path, long uid, long gid) {
        return filesystem.isWritable(path) ? -ErrorCodes.EPERM() : -ErrorCodes.EROFS();
    }

    @Override public int mknod(String path, long mode, long device) {
        return filesystem.isWritable(path) ? -ErrorCodes.EPERM() : -ErrorCodes.EROFS();
    }

    @Override public int link(String oldPath, String newPath) {
        return filesystem.isWritable(oldPath) ? -ErrorCodes.EPERM() : -ErrorCodes.EROFS();
    }

    @Override public int symlink(String target, String linkPath) {
        return filesystem.isWritable(linkPath) ? -ErrorCodes.EPERM() : -ErrorCodes.EROFS();
    }

    @Override public int setxattr(String path, String name, Pointer value, long size, int flags) {
        return filesystem.isWritable(path) ? -ErrorCodes.EOPNOTSUPP() : -ErrorCodes.EROFS();
    }

    @Override public int removexattr(String path, String name) {
        return filesystem.isWritable(path) ? -ErrorCodes.EOPNOTSUPP() : -ErrorCodes.EROFS();
    }

    @Override public int fallocate(String path, int mode, long offset, long length, FuseFileInfo info) {
        return filesystem.isWritable(path) ? -ErrorCodes.EOPNOTSUPP() : -ErrorCodes.EROFS();
    }

    @Override public int access(String path, int mask) {
        try {
            ReferenceFileSystemModel.Attributes attributes = filesystem.attributes(path);
            if ((mask & 2) != 0 && !filesystem.isWritable(path)) return -ErrorCodes.EROFS(); // W_OK
            if ((mask & 1) != 0 && !attributes.directory()) return -ErrorCodes.EACCES(); // X_OK on regular files
            return 0;
        } catch (NoSuchFileException missing) {
            return -ErrorCodes.ENOENT();
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    @Override public int releasedir(String path, FuseFileInfo info) { return 0; }

    private int publish(WriteHandle handle) {
        if (!handle.dirty) return 0;
        try {
            if (!handle.existed && filesystem.exists(handle.path)) {
                ReferenceFileSystemModel.Attributes current = filesystem.attributes(handle.path);
                if (current.directory()) return -ErrorCodes.EISDIR();
                if (current.sizeBytes() > 0) return -ErrorCodes.EEXIST();
            }
            filesystem.upload(handle.path, handle.staging, true);
            handle.dirty = false;
            return 0;
        } catch (IOException | RuntimeException failure) {
            return errno(failure);
        }
    }

    private WriteHandle handle(FuseFileInfo info) {
        if (info == null) return null;
        return handles.get(info.fh.get());
    }

    private WriteHandle openHandle(String path) {
        for (WriteHandle handle : handles.values()) {
            if (handle.path.equals(path)) return handle;
        }
        return null;
    }

    private static void truncateFile(Path file, long size) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            long current = channel.size();
            if (current > size) {
                channel.truncate(size);
            } else if (current < size) {
                if (size > 0) {
                    channel.position(size - 1);
                    channel.write(ByteBuffer.wrap(new byte[]{0}));
                }
            }
        }
    }

    private static int errno(Throwable failure) {
        if (failure instanceof NoSuchFileException) return -ErrorCodes.ENOENT();
        if (failure instanceof FileAlreadyExistsException) return -ErrorCodes.EEXIST();
        if (failure instanceof AccessDeniedException) return -ErrorCodes.EACCES();
        if (failure instanceof NotDirectoryException) return -ErrorCodes.ENOTDIR();
        if (failure instanceof DirectoryNotEmptyException) return -ErrorCodes.ENOTEMPTY();
        if (failure instanceof SecurityException) return -ErrorCodes.EACCES();
        if (failure instanceof IllegalArgumentException) return -ErrorCodes.EINVAL();
        String message = failure.getMessage() == null ? "" : failure.getMessage().toLowerCase(Locale.ROOT);
        if (message.contains("approval") || message.contains("private") || message.contains("protected")) return -ErrorCodes.EACCES();
        if (message.contains("already exists")) return -ErrorCodes.EEXIST();
        if (message.contains("offline") || message.contains("unavailable") || message.contains("host unreachable")) return -ErrorCodes.EHOSTUNREACH();
        if (message.contains("not a directory")) return -ErrorCodes.ENOTDIR();
        if (message.contains("directory")) return -ErrorCodes.EISDIR();
        return -ErrorCodes.EIO();
    }

    private static long epochSeconds(String value) {
        if (value == null || value.isBlank()) return 0;
        try { return Instant.parse(value).getEpochSecond(); }
        catch (RuntimeException ignored) { return 0; }
    }

    private static long unixId(String attribute) {
        try { return ((Number) java.nio.file.Files.getAttribute(java.nio.file.Path.of("/proc/self"), "unix:" + attribute)).longValue(); }
        catch (Exception failure) { throw new IllegalStateException("PersonalCloud FUSE requires Linux /proc unix identity attributes.", failure); }
    }

    private static final class WriteHandle {
        private final String path;
        private final Path staging;
        private final boolean existed;
        private final boolean append;
        private volatile boolean dirty;

        private WriteHandle(String path, Path staging, boolean existed, boolean append) {
            this.path = path;
            this.staging = staging;
            this.existed = existed;
            this.append = append;
        }
    }
}
