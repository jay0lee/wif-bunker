# win_dialog_accept.ps1 — Background process for CI that auto-clicks
# Windows certificate Security Warning dialogs and captures screenshots.
#
# Handles BOTH the import and removal dialogs for Root store operations.
# Uses the same SendKeys pattern as GAM's ssd.mjs:
#   https://github.com/GAM-team/GAM/blob/main/src/tools/ssd.mjs

param(
    [int]$TimeoutSeconds = 180,
    [int]$ExpectedDialogs = 2,
    [string]$ScreenshotDir = $env:GITHUB_WORKSPACE,
    [switch]$Debug
)

if (-not $ScreenshotDir) { $ScreenshotDir = $PWD }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Win32 {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
}
"@

function Take-Screenshot($label) {
    try {
        $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        if ($screen.Width -eq 0) { return }
        $bmp = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bmp.Size)
        $path = Join-Path $ScreenshotDir "$label.png"
        $bmp.Save($path)
        Write-Output "  Screenshot: $path"
        $g.Dispose()
        $bmp.Dispose()
    } catch {
        Write-Output "  Screenshot failed: $_"
    }
}

# Certificate root store dialogs are standard #32770 dialogs.
# Import shows "Security Warning", removal may show a different title.
# Match any #32770 dialog with known cert-related titles.
$CertDialogTitles = @(
    "Security Warning",
    "Root Certificate Store",
    "Certificate",
    "Windows Security"
)

function Find-CertDialog {
    $found = $null
    $foundTitle = $null
    $callback = [Win32+EnumWindowsProc] {
        param($hWnd, $lParam)
        if (-not [Win32]::IsWindowVisible($hWnd)) { return $true }

        $titleBuf = New-Object System.Text.StringBuilder 256
        [Win32]::GetWindowText($hWnd, $titleBuf, 256) | Out-Null
        $title = $titleBuf.ToString()

        $classBuf = New-Object System.Text.StringBuilder 256
        [Win32]::GetClassName($hWnd, $classBuf, 256) | Out-Null
        $class = $classBuf.ToString()

        if ($class -eq "#32770" -and $title -in $CertDialogTitles) {
            Set-Variable -Name found -Value $hWnd -Scope 1
            Set-Variable -Name foundTitle -Value $title -Scope 1
            return $false  # stop enumerating
        }
        return $true  # continue
    }
    [Win32]::EnumWindows($callback, [IntPtr]::Zero) | Out-Null
    return @{ hwnd = $found; title = $foundTitle }
}

Write-Output "Dialog auto-accept started (timeout: ${TimeoutSeconds}s)"
Write-Output "Screenshots dir: $ScreenshotDir"
Write-Output "Watching for #32770 dialogs: $($CertDialogTitles -join ', ')"

function Dump-AllWindows {
    # List all visible windows with title, class, hwnd for diagnostics
    $windows = @()
    $dumpCallback = [Win32+EnumWindowsProc] {
        param($hWnd, $lParam)
        if (-not [Win32]::IsWindowVisible($hWnd)) { return $true }
        $tb = New-Object System.Text.StringBuilder 256
        [Win32]::GetWindowText($hWnd, $tb, 256) | Out-Null
        $t = $tb.ToString()
        if ($t -eq "") { return $true }  # skip untitled windows
        $cb = New-Object System.Text.StringBuilder 256
        [Win32]::GetClassName($hWnd, $cb, 256) | Out-Null
        $c = $cb.ToString()
        $script:windows += "    hwnd=$hWnd class='$c' title='$t'"
        return $true
    }
    $script:windows = @()
    [Win32]::EnumWindows($dumpCallback, [IntPtr]::Zero) | Out-Null
    Write-Output "  === Visible windows ($($script:windows.Count)) ==="
    foreach ($w in $script:windows) { Write-Output $w }
    Write-Output "  === end ==="
}

$wshell = New-Object -ComObject wscript.shell
$elapsed = 0
$clickCount = 0

if ($Debug) { Take-Screenshot "dialog_00_start" }

while ($elapsed -lt $TimeoutSeconds) {
    $result = Find-CertDialog
    if ($result.hwnd) {
        $clickCount++
        Write-Output "Dialog #$clickCount found: '$($result.title)' (hwnd=$($result.hwnd)) at ${elapsed}s"
        if ($Debug) { Take-Screenshot "dialog_${clickCount}_found" }

        # Bring the dialog to front and focus it
        [Win32]::SetForegroundWindow($result.hwnd) | Out-Null
        Start-Sleep -Milliseconds 500

        # Send Tab+Enter to click Yes
        $wshell.SendKeys('{TAB}{ENTER}')
        Write-Output "  Clicked Yes on '$($result.title)'"

        Start-Sleep -Milliseconds 1000
        if ($Debug) {
            Take-Screenshot "dialog_${clickCount}_after"
            Dump-AllWindows
        }

        # All expected dialogs handled — stop polling
        if ($clickCount -ge $ExpectedDialogs) {
            Write-Output "All $ExpectedDialogs expected dialog(s) handled — exiting"
            break
        }

        # Brief pause to let the dialog close before polling again
        Start-Sleep -Seconds 2
        $elapsed += 2
    }

    Start-Sleep -Seconds 1
    $elapsed++

    if ($Debug -and ($elapsed % 30 -eq 0)) {
        Take-Screenshot "dialog_poll_${elapsed}s"
        Dump-AllWindows
    }
}

if ($Debug) {
    Take-Screenshot "dialog_final"
    Dump-AllWindows
}
Write-Output "Dialog auto-accept finished ($clickCount dialog(s) clicked in ${elapsed}s)"
