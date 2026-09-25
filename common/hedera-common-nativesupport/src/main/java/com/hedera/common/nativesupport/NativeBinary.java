// SPDX-License-Identifier: Apache-2.0
package com.hedera.common.nativesupport;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * <p>
 * Handles extracting of native binaries (libraries, executables, etc.) from within a JAR file based on operating system
 * and architecture.
 * <p>
 * The class provides mechanisms to extract the binary from the JAR, store it in a temporary directory on the file system,
 * and set appropriate file permissions.
 *
 * @implNote Binaries are expected to be organized within the JAR file at {@code /software/<os>/<arch>/name}.
 * This path structure is used to construct the location of the binary based on the current operating
 * system and architecture, ensuring only the correct version of the binary is extracted according to the executing environment.
 ** <p>
 * As JPMS does not allow for resources contained in a module to be loaded in a separated class it is NOT responsibility of this class
 * to retrieve the {@link InputStream} in the jar by invoking the classloader.
 * <p>
 *  Callers must use any of the suitable methods including:
 * <ul>
 * <li>{@link Class#getResourceAsStream(String)}
 * <li>{@link Module#getResourceAsStream(String)}
 * </ul>
 *
 * Example usage:
 * <pre>
 * {@code
 * NativeBinary binary = new NativeBinary("example", Map.of(), Map.of());
 * Path path = binary.extract(getClass());
 * Runtime.exec(path.toAbsolutePath().toString());
 * }
 * </pre>
 *
 * @see Architecture Current system architecture (e.g., x86, x64).
 * @see OperatingSystem Current operating system (e.g., Windows, Linux, macOS).
 */
public class NativeBinary {
    /**
     * The root resources folder where the software is located.
     * Despite the "lib" suffix, this folder may contain other types of binaries, such as native executables.
     */
    private static final String SOFTWARE_FOLDER_NAME = "com/hedera/nativelib";

    /**
     * The path delimiter used in the JAR file.
     */
    private static final String RESOURCE_PATH_DELIMITER = "/";

    /** Ensures that a library with a given name is loaded only once */
    private static final Map<String, Path> pathCache = new HashMap<>();

    private final String name;
    private final Map<OperatingSystem, String> libExtensions;
    private final Map<OperatingSystem, String> libPrefixes;

    /**
     *
     * @implNote This method expects the executable to be present at the following location in the JAR file:
     * {@code /com/hedera/nativelib/name/<os>/<arch>/name}.
     *
     * @param name the library to load.
     * @param libExtensions defaults extensions for each os to use to load the library
     */
    public NativeBinary(
            final String name,
            final Map<OperatingSystem, String> libPrefixes,
            final Map<OperatingSystem, String> libExtensions) {
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.libExtensions = Map.copyOf(Objects.requireNonNull(libExtensions, "libExtensions must not be null"));
        this.libPrefixes = Map.copyOf(Objects.requireNonNull(libPrefixes, "libPrefixes must not be null"));
    }

    /**
     * Returns the library name.
     *
     * @return the library name
     */
    public String name() {
        return this.name;
    }

    /**
     * Constructs the relative path within the JAR file for the library based on the operating system and architecture.
     *
     * @return A string representing the relative path.
     */
    public String locationInJar() {
        return locationInJar(this.name, this.libPrefixes, this.libExtensions);
    }

    /**
     * Static helper to construct the library path in the JAR file for a given library name and extensions map.
     *
     * @param libraryName The name of the library.
     * @param libPrefixes Library file prefixes for each operating system.
     * @param libExtensions Library file extensions for each operating system.
     * @return The path to the library in the JAR file.
     */
    public static String locationInJar(
            final String libraryName,
            final Map<OperatingSystem, String> libPrefixes,
            final Map<OperatingSystem, String> libExtensions) {
        Objects.requireNonNull(libraryName, "name must not be null");
        Objects.requireNonNull(libPrefixes, "libPrefixes must not be null");
        Objects.requireNonNull(libExtensions, "libExtensions must not be null");
        final OperatingSystem os = OperatingSystem.current();
        final Architecture arch = Architecture.current();

        final String libPrefix = libPrefixes.getOrDefault(os, "");

        String libExtension = libExtensions.get(os);
        if (libExtension != null && !libExtension.isEmpty()) {
            libExtension = "." + libExtension;
        } else {
            libExtension = "";
        }
        return SOFTWARE_FOLDER_NAME
                + RESOURCE_PATH_DELIMITER
                + libraryName.toLowerCase(Locale.US)
                + RESOURCE_PATH_DELIMITER
                + os.name().toLowerCase(Locale.US)
                + RESOURCE_PATH_DELIMITER
                + arch.name().toLowerCase(Locale.US)
                + RESOURCE_PATH_DELIMITER
                + libPrefix
                + libraryName
                + libExtension;
    }

    /// Return the package name where the native library is located.
    public String packageNameOfResource() {
        return ResourceFile.packageNameOfResource(locationInJar());
    }

    /**
     * Unpackages the native binary to a temporary dir, sets appropriate file permissions, and returns the Path
     * to the extracted file. The temporary directory is configured to be deleted on exit.
     *
     * @param c the class whose module contains the native library
     * @throws IllegalStateException if the module does not open the package where the resource is located
     */
    public Path extract(final Class<?> c) {
        if (!c.getModule().isOpen(packageNameOfResource(), this.getClass().getModule())) {
            // getResourceAsStream() will not throw an exception if the package is not opened, it will just return null
            // so we manually check if the package is opened
            throw new IllegalStateException("The module '%s' must open the package '%s' to module '%s'"
                    .formatted(
                            c.getModule().getName(),
                            packageNameOfResource(),
                            this.getClass().getModule().getName()));
        }
        synchronized (pathCache) {
            return pathCache.computeIfAbsent(name, k -> {
                Path path = ResourceFile.extract(c, locationInJar(), "r-x------");
                postExtract(path);
                return path;
            });
        }
    }

    /// Post-extract actions. For example, a descendant might call System.load() to load a native library.
    protected void postExtract(final Path path) {
        // no-op by default
    }
}
