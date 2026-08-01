# win_dialog_accept.ps1 — Background process for CI that auto-clicks
# Windows certificate "Security Warning" dialogs and captures screenshots.
#
# Based on the SendKeys pattern from GAM's ssd.mjs:
#   https://github.com/GAM-team/GAM/blob/main/src/tools/ssd.mjs

param(
    [int]$TimeoutSeconds = 180,
    [string]$ScreenshotDir = $env:GITHUB_WORKSPACE
)

if (-not $ScreenshotDir) { $ScreenshotDir = $PWD }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Use Win32 API for precise window matching instead of AppActivate
# which does substring matching and can grab wrong windows (e.g. OOBE).
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

function Find-SecurityWarningDialog {
    # Find a window with EXACT title "Security Warning" that is a dialog
    # (class #32770). This avoids matching the OOBE or other windows.
    $found = $null
    $callback = [Win32+EnumWindowsProc] {
        param($hWnd, $lParam)
        if (-not [Win32]::IsWindowVisible($hWnd)) { return $true }

        $titleBuf = New-Object System.Text.StringBuilder 256
        [Win32]::GetWindowText($hWnd, $titleBuf, 256) | Out-Null
        $title = $titleBuf.ToString()

        $classBuf = New-Object System.Text.StringBuilder 256
        [Win32]::GetClassName($hWnd, $classBuf, 256) | Out-Null
        $class = $classBuf.ToString()

        # The cert root store security warning is a standard dialog (#32770)
        # with exact title "Security Warning"
        if ($title -eq "Security Warning" -and $class -eq "#32770") {
            Set-Variable -Name found -Value $hWnd -Scope 1
            return $false  # stop enumerating
        }
        return $true  # continue
    }
    [Win32]::EnumWindows($callback, [IntPtr]::Zero) | Out-Null
    return $found
}

Write-Output "Dialog auto-accept started (timeout: ${TimeoutSeconds}s)"
Write-Output "Screenshots dir: $ScreenshotDir"
Write-Output "Looking for exact title 'Security Warning' with class '#32770'"

$elapsed = 0
$clickCount = 0

Take-Screenshot "dialog_00_start"

while ($elapsed -lt $TimeoutSeconds) {
    $hwnd = Find-SecurityWarningDialog
    if ($hwnd) {
        $clickCount++
        Write-Output "Dialog #$clickCount found (hwnd=$hwnd) at ${elapsed}s"
        Take-Screenshot "dialog_${clickCount}_found"

        # Bring the dialog to front and focus it
        [Win32]::SetForegroundWindow($hwnd) | Out-Null
        Start-Sleep -Milliseconds 500

        # Send Tab+Enter to click Yes (Yes is not the default button)
        $wshell = New-Object -ComObject wscript.shell
        $wshell.SendKeys('{TAB}{ENTER}')
        Write-Output "  Sent Tab+Enter"

        Start-Sleep -Milliseconds 1000
        Take-Screenshot "dialog_${clickCount}_after"
    }

    Start-Sleep -Seconds 1
    $elapsed++

    # Periodic screenshots every 30s
    if ($elapsed % 30 -eq 0) {
        Take-Screenshot "dialog_poll_${elapsed}s"
    }
}

Take-Screenshot "dialog_final"
Write-Output "Dialog auto-accept finished ($clickCount dialog(s) clicked in ${elapsed}s)"
