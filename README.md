# AlgoLassi File Recovery

Windows file-recovery utility written in C# / .NET 9 WinForms.

## Current branch

`0.1-recovery-foundation`

## Current functionality

- Lists items that are still present in the Windows Recycle Bin.
- Shows the file name and best-effort Shell metadata such as original location, deletion date, and size.
- Restores selected Recycle Bin items using the Windows Shell restore operation.
- Does not read raw disk sectors.
- Does not write to raw sectors or directly modify the source drive.

The Recycle Bin is a Windows Shell virtual folder. This first version deliberately uses the Shell restore operation rather than attempting raw-disk recovery.

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
2. Safe NTFS metadata inspection
3. NTFS deleted-file discovery
4. Deep file-signature scanning
5. Preview and recover-to-another-drive workflow
6. Code signing and public release packaging

Recovery software cannot guarantee recovery of every deleted file. SSD TRIM and overwritten data can make deleted data unrecoverable.