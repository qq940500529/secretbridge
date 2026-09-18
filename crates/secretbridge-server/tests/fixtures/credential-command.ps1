# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
param([string]$Mode, [string]$Value, [string]$Extra)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
if ($Mode -eq 'sleep') { Start-Sleep -Seconds 15; exit 0 }
if ($Mode -eq 'stdin') { $Value = [Console]::In.ReadToEnd() }
if ($Mode -eq 'environment') { $Value = $env:SB_TEST_SECRET }
if ($Mode -eq 'file') { $Value = [System.IO.File]::ReadAllText($Value) }
for ($i = 0; $i -lt $Value.Length; $i++) {
    [Console]::Out.Write($Value[$i]); [Console]::Out.Flush()
    Start-Sleep -Milliseconds 2
}
[Console]::Out.WriteLine('|stdout-marker|')
[Console]::Error.WriteLine($Value + '|stderr-marker|')
if ($Extra) { [Console]::Out.WriteLine('|parameter:' + $Extra + '|') }
