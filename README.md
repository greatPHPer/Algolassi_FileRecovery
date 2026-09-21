# AlgoLassi File Recovery

Windows file-recovery utility written in C# / .NET 9 WinForms.

## Current branch

`0.2-background-monitor`

## Background monitor

When the app is running, it stays in the Windows notification area (system tray) and monitors ready NTFS fixed volumes for file-system deletion notifications.

When a deletion is observed:

- A deletion record is saved under the current user's local application data.
- The latest deleted directory is shown in the Recovery Center.
- A small bottom-right notification can slide into view.
- Notifications can be muted without stopping monitoring.
- The app keeps the latest 500 deletion records.

The live monitor currently uses `FileSystemWatcher` to capture the exact path supplied by Windows. This is intentionally the first layer of monitoring. A future NTFS USN-journal catch-up layer can fill gaps when the application was not running and can make monitoring more resilient to notification-buffer overflow.

## Recovery Center

The main window can be opened from the tray icon and shows:

- Recent directories with deletions
- Recorded deleted files
- Deleted timestamp
- Best-known file size
- Recovery-strength estimate
- Current Windows Recycle Bin items for a selected directory

Items still present in the Windows Recycle Bin are shown as a strong recovery signal because Windows can restore them directly. A deletion that is no longer represented in the Recycle Bin is currently shown as a weak signal; this is only an estimate and is not a guarantee about raw-disk recoverability.

The current recovery implementation does not read raw disk sectors and does not perform NTFS file carving yet.

## Standalone EXE

The project is configured for a self-contained `win-x64` single-file publish:

```powershell
dotnet publish .\FileRecovery\FileRecovery.csproj -c Release -r win-x64 --self-contained true
```

Publish output:

```text
FileRecovery\bin\Release\net9.0-windows\win-x64\publish\
```

## Roadmap

1. Recycle Bin recovery
2. Resident deletion monitor
3. NTFS USN-journal catch-up
4. Safe NTFS metadata inspection
5. NTFS deleted-file discovery
6. Deep file-signature scanning
7. Preview and recover-to-another-drive workflow
8. Code signing and public release packaging

Recovery software cannot guarantee recovery of every deleted file. SSD TRIM and overwritten data can make deleted data unrecoverable.
