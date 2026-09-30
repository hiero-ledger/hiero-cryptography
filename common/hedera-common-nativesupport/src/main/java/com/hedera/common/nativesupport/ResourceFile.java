// SPDX-License-Identifier: Apache-2.0
package com.hedera.common.nativesupport;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.ProviderNotFoundException;
import java.nio.file.attribute.PosixFilePermissions;

/// A utility to extract a file from JAR resources and store it in a temporary directory
/// in the local file system.
/// Additionally, static utility methods to create temporary directories and set file permissions
/// are provided to support this operation.
public final class ResourceFile {
    private ResourceFile() {}

    /// Creates a new temporary directory, extracts the file into it, and returns its Path.
    /// The file must reside in a package that is open to the module of the ResourceFile class.
    /// E.g. use clz.getModule().addOpens("package.name", ResourceFile.getModule()).
    public static Path extract(final Class<?> clz, String filePathInJar, String filePosixPermissions) {
        final String packageName = packageNameOfResource(filePathInJar);
        if (!clz.getModule().isOpen(packageName, ResourceFile.class.getModule())) {
            // getResourceAsStream() will not throw an exception if the package is not opened, it will just return null
            // so we manually check if the package is opened
            throw new IllegalStateException("The module '%s' must open the package '%s' to module '%s'"
                    .formatted(
                            clz.getModule().getName(),
                            packageName,
                            ResourceFile.class.getModule().getName()));
        }

        try (InputStream resourceStream = clz.getModule().getResourceAsStream(filePathInJar)) {
            final String fileName = Path.of(filePathInJar).getFileName().toString();

            final Path tempDirectory = createTempDirectory(fileName);
            final Path tempFile = tempDirectory.resolve(fileName);

            Files.copy(resourceStream, tempFile);

            setPermissions(tempFile, filePosixPermissions);
            tempFile.toFile().deleteOnExit();

            return tempFile;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /// Copied from jdk.internal.module.Resources.toPackageName() since the method is not open to the public.
    /// @param name a full file path in jar
    /// @return the package name where the native library is located
    public static String packageNameOfResource(String name) {
        int index = name.lastIndexOf('/');
        if (index == -1 || index == name.length() - 1) {
            return "";
        } else {
            return name.substring(0, index).replace('/', '.');
        }
    }

    /// Create a temporary directory for the requester with a given name and `rwx------` permissions.
    /// The directory is deleted when JVM exits.
    /// @return the path to the temporary directory.
    /// @throws IOException if the temporary directory cannot be created or an I/O error occurs.
    @SuppressWarnings("ResultOfMethodCallIgnored")
    public static Path createTempDirectory(String name) throws IOException {
        // Unfortunately, we cannot set permissions on the createTempDirectory call atomically
        // because Windows doesn't support posix permissions. So we set permissions below instead:
        final Path tempDirectory = Files.createTempDirectory(name);
        tempDirectory.toFile().mkdir();
        ResourceFile.setPermissions(tempDirectory, "rwx------");
        tempDirectory.toFile().deleteOnExit();
        return tempDirectory;
    }

    private record WindowsPermission(boolean enabled, boolean ownerOnly) {
        // posixPermissions MUST be 9 characters long. It's caller's responsibility to ensure that.
        static WindowsPermission of(final String posixPermissions, final char c) {
            final int pos =
                    switch (c) {
                        case 'r' -> 0;
                        case 'w' -> 1;
                        case 'x' -> 2;
                        default -> throw new IllegalArgumentException("Unknown permission character: " + c);
                    };

            final boolean enabled = posixPermissions.charAt(pos) == c
                    || posixPermissions.charAt(pos + 3) == c
                    || posixPermissions.charAt(pos + 6) == c;

            final boolean ownerOnly = posixPermissions.charAt(pos) == c
                    && posixPermissions.charAt(pos + 3) != c
                    && posixPermissions.charAt(pos + 6) != c;

            return new WindowsPermission(enabled, ownerOnly);
        }
    }

    /// Sets posix permissions on a given Path.
    /// If the native system isn't posix-compliant, then the permissions are translated
    /// to the native format (i.e. to Windows).
    public static void setPermissions(final Path path, final String posixPermissions) throws IOException {
        if (path == null || posixPermissions == null || posixPermissions.length() != 9) {
            throw new IllegalArgumentException(
                    "Null path/posixPermissions, or posixPermissions is not 9 characters long");
        }
        if (isPosixCompliant()) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(posixPermissions));
        } else {
            final WindowsPermission executable = WindowsPermission.of(posixPermissions, 'x');
            final WindowsPermission readable = WindowsPermission.of(posixPermissions, 'r');
            final WindowsPermission writable = WindowsPermission.of(posixPermissions, 'w');
            final File f = path.toFile();
            f.setExecutable(executable.enabled, executable.ownerOnly);
            f.setReadable(readable.enabled, readable.ownerOnly);
            f.setWritable(writable.enabled, writable.ownerOnly);
        }
    }

    /// Is the system we're running on Posix compliant?
    static boolean isPosixCompliant() {
        try {
            return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
        } catch (FileSystemNotFoundException | ProviderNotFoundException | SecurityException e) {
            return false;
        }
    }
}
