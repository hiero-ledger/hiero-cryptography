// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/// Utility to run a Rust executable
class DataCruncher {
    /// 3 hours seems more than enough
    private static final long PROCESS_WAIT_TIMEOUT_MILLIS = 3 * 60 * 60 * 1000;

    /// Full path to static parameters of the current cycle shared between all phases/nodes/runs.
    private final Path parametersPath;

    DataCruncher(Path parametersPath) {
        this.parametersPath = parametersPath;
    }

    /// Run the data cruncher and return its exit code
    int execute(String phase, Path inputPath, Path outputPath) throws IOException {
        final ProcessBuilder pb = new ProcessBuilder()
                .command(
                        CeremonyExecutable.EXECUTABLE_PATH.toAbsolutePath().toString(),
                        phase,
                        parametersPath.toAbsolutePath().toString(),
                        inputPath.toAbsolutePath().toString(),
                        outputPath.toAbsolutePath().toString());

        final Process process = pb.start();
        try {
            if (!process.waitFor(PROCESS_WAIT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)) {
                System.err.println("Timed out waiting for process");
                process.destroy();
                process.waitFor(1, TimeUnit.SECONDS);
                process.destroyForcibly();
                return Integer.MIN_VALUE;
            }
        } catch (InterruptedException e) {
            process.destroy();
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            return Integer.MIN_VALUE;
        }

        return process.exitValue();
    }
}
