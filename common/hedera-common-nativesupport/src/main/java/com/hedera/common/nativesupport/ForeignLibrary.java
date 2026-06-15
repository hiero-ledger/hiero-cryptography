// SPDX-License-Identifier: Apache-2.0
package com.hedera.common.nativesupport;

import java.lang.foreign.Arena;
import java.lang.foreign.SymbolLookup;
import java.nio.file.Path;
import java.util.Map;

/**
 * <p>
 * Handles loading of foreign binary libraries from within a JAR file based on operating system and architecture
 * for use with Java FFM APIs.
 * <p>
 * Example usage:
 * <pre>
 * {@code
 * ForeignLibrary library = ForeignLibrary.withName("example");
 * SymbolLookup lookup = library.lookup(getClass(), myArena);
 * }
 * </pre>
 *
 * @see Architecture Current system architecture (e.g., x86, x64).
 * @see OperatingSystem Current operating system (e.g., Windows, Linux, macOS).
 */
public class ForeignLibrary extends NativeBinary {

    /**
     *
     * @implNote This method expects the executable to be present at the following location in the JAR file:
     * {@code /com/hedera/nativelib/name/<os>/<arch>/name}.
     *
     * @param name the library to load.
     * @param libExtensions defaults extensions for each os to use to load the library
     */
    protected ForeignLibrary(
            final String name,
            final Map<OperatingSystem, String> libPrefixes,
            final Map<OperatingSystem, String> libExtensions) {
        super(name, libPrefixes, libExtensions);
    }

    /**
     * Factory method to create a ForeignLibrary instance with custom library extensions.
     *
     * @param name The name of the library.
     * @param libPrefixes Custom library file prefixes for each operating system.
     * @param libExtensions Custom library file extensions for each operating system.
     * @return An instance of ForeignLibrary.
     */
    public static ForeignLibrary withName(
            final String name,
            final Map<OperatingSystem, String> libPrefixes,
            final Map<OperatingSystem, String> libExtensions) {
        return new ForeignLibrary(name, libPrefixes, libExtensions);
    }

    /**
     * Factory method to create a {@link ForeignLibrary} instance using default library extensions.
     *
     * @param name The name of the library.
     * @return An instance of ForeignLibrary.
     */
    public static ForeignLibrary withName(final String name) {
        return withName(name, NativeLibrary.DEFAULT_LIB_PREFIXES, NativeLibrary.DEFAULT_LIB_EXTENSIONS);
    }

    /**
     * Unpackages the native library to a temporary dir, sets appropriate file permissions, and loads the library into
     * the JVM.
     * <p>
     * Technically, an application may call this method multiple times, even with different arenas, and the JVM/OS
     * will take care of loading the native library only once. The `NativeBinary` would also take care of unpacking
     * the binary file from the .JAR file only once. However, generally this is discouraged because a single
     * `SymbolLookup` instance should suffice for most applications.
     *
     * @param c the class whose module contains the native library
     * @param arena an arena that controls the lifecycle of the lookup.
     * @return a SymbolLookup instance to find symbols exported by the library
     * @throws IllegalStateException if the module does not open the package where the resource is located
     */
    @SuppressWarnings("restricted") // SymbolLookup.libraryLookup() is restricted
    public SymbolLookup lookup(final Class<?> c, final Arena arena) {
        final Path path = extract(c);
        return SymbolLookup.libraryLookup(path, arena);
    }
}
