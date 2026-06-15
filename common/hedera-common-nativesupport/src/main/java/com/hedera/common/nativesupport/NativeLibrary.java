// SPDX-License-Identifier: Apache-2.0
package com.hedera.common.nativesupport;

import java.nio.file.Path;
import java.util.Map;

/**
 * <p>
 * Handles loading of native binary libraries from within a JAR file based on operating system and architecture.
 * <p>
 * Since it is not possible to directly {@link System#load(String)} a library from within a JAR, this class facilitates
 * the extraction and loading of these libraries when they are not pre-installed on the operating system.
 * <p>
 * This class inherits from the {@code NativeBinary} class which handles the actual extraction of the binary file
 * with the library from the JAR file, and adds a call to {@code System.load()} in order to load the library
 * into the JVM process.
 * <p>
 * Example usage:
 * <pre>
 * {@code
 * NativeLibrary library = NativeLibrary.withName("example");
 * library.install(getClass());
 * }
 * </pre>
 *
 * @see Architecture Current system architecture (e.g., x86, x64).
 * @see OperatingSystem Current operating system (e.g., Windows, Linux, macOS).
 */
public class NativeLibrary extends NativeBinary {
    /**
     * Default extensions for binary libraries per OS
     */
    public static final Map<OperatingSystem, String> DEFAULT_LIB_EXTENSIONS =
            Map.of(OperatingSystem.WINDOWS, "dll", OperatingSystem.LINUX, "so", OperatingSystem.DARWIN, "dylib");

    /**
     * Default prefix for binary libraries per OS
     */
    public static final Map<OperatingSystem, String> DEFAULT_LIB_PREFIXES =
            Map.of(OperatingSystem.WINDOWS, "", OperatingSystem.LINUX, "lib", OperatingSystem.DARWIN, "lib");

    /**
     *
     * @implNote This method expects the executable to be present at the following location in the JAR file:
     * {@code /com/hedera/nativelib/name/<os>/<arch>/name}.
     *
     * @param name the library to load.
     * @param libExtensions defaults extensions for each os to use to load the library
     */
    private NativeLibrary(
            final String name,
            final Map<OperatingSystem, String> libPrefixes,
            final Map<OperatingSystem, String> libExtensions) {
        super(name, libPrefixes, libExtensions);
    }

    /**
     * Factory method to create a NativeLibrary instance with custom library extensions.
     *
     * @param name The name of the library.
     * @param libPrefixes Custom library file prefixes for each operating system.
     * @param libExtensions Custom library file extensions for each operating system.
     * @return An instance of NativeLibrary.
     */
    public static NativeLibrary withName(
            final String name,
            final Map<OperatingSystem, String> libPrefixes,
            final Map<OperatingSystem, String> libExtensions) {
        return new NativeLibrary(name, libPrefixes, libExtensions);
    }

    /**
     * Factory method to create a {@link NativeLibrary} instance using default library extensions.
     *
     * @param name The name of the library.
     * @return An instance of NativeLibrary.
     */
    public static NativeLibrary withName(final String name) {
        return withName(name, DEFAULT_LIB_PREFIXES, DEFAULT_LIB_EXTENSIONS);
    }

    /**
     * Unpackages the native library to a temporary dir, sets appropriate file permissions, and loads the library into
     * the JVM.
     *
     * @param c the class whose module contains the native library
     * @throws IllegalStateException if the module does not open the package where the resource is located
     */
    public void install(final Class<?> c) {
        extract(c);
    }

    /**
     * Override the NativeBinary.extractUnchecked() to also System.load() the extracted library.
     */
    @SuppressWarnings("restricted")
    @Override
    protected Path extractUnchecked(final Class<?> c) {
        final Path path = super.extractUnchecked(c);
        System.load(path.toAbsolutePath().toString());
        return path;
    }
}
