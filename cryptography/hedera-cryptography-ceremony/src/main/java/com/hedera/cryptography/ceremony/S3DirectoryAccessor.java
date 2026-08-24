// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import com.hedera.cryptography.ceremony.s3.S3Client;
import com.hedera.cryptography.ceremony.s3.S3ResponseException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

/// Utility for accessing a directory inside an S3 bucket for TSS Ceremony.
class S3DirectoryAccessor {
    /// When waiting for a file in S3 bucket, wait this long between checks:
    private static final long WAIT_BETWEEN_CHECKS_MILLIS = 60 * 1000;

    /// S3 storage class
    private static final String STORAGE_CLASS = "STANDARD";

    /// The max num of objects that S3Client.listObjects() supports today:
    private static final int MAX_OBJECTS = 1000;

    private static final String BINARY_CONTENT_TYPE = "application/octet-stream";

    private final S3Client s3Client;
    private final String dir;

    S3DirectoryAccessor(S3Client s3Client, String dir) {
        this.s3Client = s3Client;
        this.dir = ensureSlash(dir);
    }

    /// Check if bucket/dir/fileName exists in S3.
    boolean doesExist(String fileName) throws IOException {
        try {
            final String name = dir + fileName;
            final List<String> objects = s3Client.listObjects(name, 2);
            // The name must be unique, meaning that it cannot be a directory,
            // and there cannot be longer filenames with the same prefix:
            return objects.size() == 1 && objects.get(0).equals(name);
        } catch (S3ResponseException e) {
            throw new IOException(e);
        }
    }

    /// Wait for bucket/dir/fileName to appear within timeoutMillis, or return false.
    boolean waitForFile(String fileName, long timeoutMillis) throws IOException {
        final long startTimeMillis = System.currentTimeMillis();
        do {
            if (doesExist(fileName)) {
                return true;
            }
            try {
                // The negative timeout is to support unit tests with very short timeouts:
                Thread.sleep(timeoutMillis < 0 ? 1 : WAIT_BETWEEN_CHECKS_MILLIS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                System.err.println(ie.getMessage());
                return false;
            }
        } while (System.currentTimeMillis() - startTimeMillis < Math.abs(timeoutMillis));
        System.err.println("timeout");
        return false;
    }

    /// Write `text` to bucket/dir/fileName .
    void writeText(String fileName, String text) throws IOException {
        try {
            s3Client.uploadTextFile(dir + fileName, STORAGE_CLASS, text);
        } catch (S3ResponseException e) {
            throw new IOException(e);
        }
    }

    /// Download all files from bucket/dir/directoryName/* in S3 to a temp directory in local file system.
    Path downloadDir(String directoryName) throws IOException {
        final Path path = Files.createTempDirectory(directoryName);

        try {
            final String prefix = dir + ensureSlash(directoryName);

            final List<String> objects = s3Client.listObjects(prefix, MAX_OBJECTS);
            for (String object : objects) {
                if (prefix.equals(object)) {
                    // An edge case if the directory itself is present in the list.
                    continue;
                }

                // The validation ensures that nested subdirectories are NOT supported.
                // This is by design:
                final String fileName = validateFileName(object.substring(prefix.length()));
                s3Client.downloadFile(object, path.resolve(fileName));
            }

            return path;
        } catch (S3ResponseException e) {
            throw new IOException(e);
        }
    }

    /// Ensure the given fileName is just a file name, w/o any special characters
    /// such as path separators or double periods.
    /// @throws IllegalArgumentException if the fileName has invalid characters
    static String validateFileName(String fileName) {
        if (fileName.contains(File.pathSeparator) || fileName.contains(File.separator) || fileName.contains("..")) {
            throw new IllegalArgumentException(
                    "fileName shouldn't contain path or file separators, or path following characters. Instead got (w/o ` quotes): `"
                            + fileName + "`");
        }
        return fileName;
    }

    /// Upload all files from filesDir/* on local disk to bucket/dir/directoryName/ in S3.
    /// Nested directories are NOT supported.
    void uploadDir(Path filesDir, String directoryName) throws IOException {
        final String prefix = dir + ensureSlash(directoryName);

        // Must close() the stream to release resources!
        try (final Stream<Path> filesStream = Files.walk(filesDir)) {
            // Easier to handle exceptions in a loop than from stream.forEach():
            final List<Path> files = filesStream.toList();
            for (Path path : files) {
                if (path.equals(filesDir)) continue;

                final String fileName = path.getFileName().toString();
                try (final FileBytesIterator fileBytesIterator = new FileBytesIterator(path)) {
                    s3Client.uploadFile(prefix + fileName, STORAGE_CLASS, fileBytesIterator, BINARY_CONTENT_TYPE);
                } catch (S3ResponseException e) {
                    throw new IOException(e);
                }
            }
        }
    }

    private String ensureSlash(String path) {
        return path.endsWith("/") ? path : path + "/";
    }
}
