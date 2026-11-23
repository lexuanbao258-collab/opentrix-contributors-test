// SPDX-FileCopyrightText: 2026 TRICORE contributors
//
// SPDX-License-Identifier: Apache-2.0

package com.tricore.dxos.infrastructure.workflow;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Launcher tests start Windows PowerShell 5.1 ({@code powershell.exe}) from the JVM. When Gradle itself was
 * started from PowerShell 7, the inherited PSModulePath lists PowerShell 7 module directories first, so
 * Windows PowerShell autoloads the Core-only {@code Microsoft.PowerShell.Security} module and every
 * cmdlet from it ({@code ConvertTo-SecureString}, {@code Get-Acl}, {@code Set-Acl}) fails to load.
 * PowerShell 7 strips its own paths when it starts {@code powershell.exe} directly; a JVM child does not.
 */
@EnabledOnOs(value = OS.WINDOWS, disabledReason = "Launches Windows PowerShell (powershell.exe)")
class WindowsPowerShellChildTest {
    @TempDir Path temporary;

    /** Drops the inherited PSModulePath so Windows PowerShell rebuilds its own default module path. */
    static ProcessBuilder isolate(ProcessBuilder builder) {
        builder.environment().keySet().removeIf(key -> key.equalsIgnoreCase("PSModulePath"));
        return builder;
    }

    @Test
    void securityCmdletsLoadDespiteInheritedPowerShell7ModulePath() throws Exception {
        // Stand-in for C:\Program Files\PowerShell\7\Modules: a Core-only module shadowing the Desktop one.
        Path module = Files.createDirectories(temporary.resolve("pwsh7-modules/Microsoft.PowerShell.Security"));
        Files.writeString(module.resolve("Microsoft.PowerShell.Security.psd1"), "@{ ModuleVersion='7.0.0.0';"
                + " GUID='a94c8c7e-9810-47c0-b8af-65089c13a35a'; PowerShellVersion='7.0'; CompatiblePSEditions=@('Core');"
                + " CmdletsToExport=@('ConvertTo-SecureString','Get-Acl','Set-Acl') }\r\n");
        String poisoned = module.getParent() + File.pathSeparator + System.getenv().getOrDefault("PSModulePath", "");

        assertThat(run(poisoned, false)).contains("SECURITY_MODULE=FAIL");
        assertThat(run(poisoned, true)).contains("SECURITY_MODULE=OK");
    }

    private String run(String modulePath, boolean isolated) throws Exception {
        var builder = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                "try { ConvertTo-SecureString x -AsPlainText -Force | Out-Null; Get-Acl -LiteralPath . | Out-Null;"
                        + " 'SECURITY_MODULE=OK' } catch { 'SECURITY_MODULE=FAIL' }")
                .directory(temporary.toFile()).redirectErrorStream(true);
        builder.environment().keySet().removeIf(key -> key.equalsIgnoreCase("PSModulePath"));
        builder.environment().put("PSModulePath", modulePath);
        if (isolated) isolate(builder);
        var process = builder.start();
        try {
            assertThat(process.waitFor(30, TimeUnit.SECONDS)).isTrue();
            return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        } finally { if (process.isAlive()) process.destroyForcibly(); }
    }
}
