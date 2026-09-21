# AlgoLassi File Recovery

Windows file-recovery utility written in C# / .NET 9 WinForms.

## Current branch

`0.5-ntfs-data-run-analysis`

## Background monitor

When the app is running, it stays in the Windows notification area (system tray) and monitors ready NTFS fixed volumes for file-system deletion notifications.

When a deletion is observed:

- A deletion record is saved under the current user's local application data.
- The latest deleted directory is shown in the Recovery Center.
- A small bottom-right notification can slide into view.
- Notifications can be muted without stopping monitoring.
- The app keeps the latest 500 deletion records.

The live monitor uses `FileSystemWatcher` to capture the affected item's fully qualified path. Windows exposes that path through `FileSystemEventArgs.FullPath`, including the deleted filename and its parent directory.

Windows Recycle Bin operations are handled separately because a normal Delete-to-Recycle-Bin operation can be represented as a move/rename rather than a permanent filesystem delete. A small Recycle Bin monitor polls the Shell contents and records newly appeared items using the original location, filename, deleted date, and size.

A second NTFS USN-journal layer is enabled for catch-up. Each USN delete record contains the deleted filename and the parent directory's NTFS file identifier. The app opens that parent directory by file ID and resolves its final filesystem path. This allows the app to reconstruct the deleted directory even though the deleted file itself no longer exists.

USN journal operations require administrator privileges on Windows. If the app is not elevated, the live `FileSystemWatcher` and Recycle Bin monitoring remain available, while USN catch-up reports a permission warning in the app status area.

## Recovery Center

The main window can be opened from the tray icon and shows:

- Recent directories with deletions
- Recorded deleted files
- Deleted timestamp
- Best-known file size
- Recovery-strength estimate
- Current Windows Recycle Bin items for a selected directory

Items still present in the Windows Recycle Bin are shown as a strong recovery signal because Windows can restore them directly. A deletion that is no longer represented in the Recycle Bin is currently shown as a weak signal; this is only an estimate and is not a guarantee about raw-disk recoverability.

### NTFS volume inspection

The recovery foundation now includes a safe NTFS volume inspector using `FSCTL_GET_NTFS_VOLUME_DATA`. Windows exposes the volume's sector size, cluster size, file-record segment size, total/free clusters, MFT valid length, and MFT start/mirror locations through `NTFS_VOLUME_DATA_BUFFER`.

This stage only reads filesystem metadata. It does not read deleted-file clusters and does not write anything to the source volume.

### NTFS deleted-file candidate scan

The Recovery Center now includes **Scan NTFS Deleted Files**. On an NTFS source volume, the scanner uses `FSCTL_ENUM_USN_DATA` to enumerate MFT/USN metadata and identifies records carrying `USN_REASON_FILE_DELETE`. Microsoft documents `FSCTL_ENUM_USN_DATA` as an MFT-record enumeration mechanism for NTFS volumes.

The scanner resolves the deleted record's parent directory by its NTFS file reference when possible. The current recovery foundation now also reads the retained MFT record for the candidate and inspects the unnamed `$DATA` attribute. A resident stream is kept inside the MFT record; a nonresident stream contains VCN-to-LCN mapping-pairs that describe former cluster locations.

Results are still candidates only: this stage does not claim the former clusters are intact, and it does not reconstruct or write recovered files.

Recovery output is intentionally designed around a different destination volume. The destination policy rejects a recovery target on the same drive as the source, which reduces the risk of overwriting clusters that might still contain recoverable data.

The current branch does not yet perform raw-cluster reads, file-signature carving, or byte-level reconstruction.

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
6. NTFS volume/record inspection
7. NTFS candidate-to-cluster mapping
8. Deep file-signature scanning
9. Preview and recover-to-another-drive workflow
10. Code signing and public release packaging

Recovery software cannot guarantee recovery of every deleted file. SSD TRIM and overwritten data can make deleted data unrecoverable.
