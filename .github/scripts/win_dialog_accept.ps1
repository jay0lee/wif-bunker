# win_dialog_accept.ps1 — Background process for CI that auto-clicks
# Windows "Security Warning" dialogs and captures screenshots.
#
# Usage (launch as background job in the same step as wif_bunker.py):
#   Start-Job -FilePath .github\scripts\win_dialog_accept.ps1
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

# Possible dialog window titles for cert root store operations
$dialogTitles = @(
    'Security Warning',
    'Root Certificate Store',
    'Certificate',
    'Windows Security'
)

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

Write-Output "Dialog auto-accept started (timeout: ${TimeoutSeconds}s)"
Write-Output "Screenshots dir: $ScreenshotDir"
Write-Output "Watching for titles: $($dialogTitles -join ', ')"

$wshell = New-Object -ComObject wscript.shell
$elapsed = 0
$clickCount = 0

# Take an initial screenshot to verify the desktop is visible
Take-Screenshot "dialog_00_start"

while ($elapsed -lt $TimeoutSeconds) {
    foreach ($title in $dialogTitles) {
        $found = $false
        try {
            $found = $wshell.AppActivate($title)
        } catch {
            # AppActivate can throw if no matching window
        }

        if ($found) {
            $clickCount++
            Write-Output "Dialog #$clickCount found: '$title' at ${elapsed}s"
            Take-Screenshot "dialog_${clickCount}_found"

            # Small delay to ensure the window is fully focused
            Start-Sleep -Milliseconds 500

            # The Security Warning dialog has Yes/No buttons.
            # Yes is NOT the default — Tab to it, then Enter.
            $wshell.SendKeys('{TAB}{ENTER}')
            Write-Output "  Sent Tab+Enter"

            Start-Sleep -Milliseconds 1000
            Take-Screenshot "dialog_${clickCount}_after"

            # Don't exit — there may be a second dialog (CA removal).
            break
        }
    }

    Start-Sleep -Seconds 1
    $elapsed++

    # Periodic screenshots every 30s for debugging
    if ($elapsed % 30 -eq 0) {
        Take-Screenshot "dialog_poll_${elapsed}s"
    }
}

Take-Screenshot "dialog_final"
Write-Output "Dialog auto-accept finished ($clickCount dialog(s) clicked in ${elapsed}s)"
