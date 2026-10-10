using System.Text.Json;

namespace FileRecovery;

public sealed class RecoverySettings
{
    public bool NotificationsMuted { get; set; }
    public List<string> IgnoredDirectories { get; set; } = [];
    public List<string> ProtectedDirectories { get; set; } = [];

    // The rolling pre-delete cache and promoted snapshots share this storage root.
    // The default is used only after the user explicitly enables protected folders.
    public string PreDeleteStorageDirectory { get; set; } = string.Empty;
    public long PreDeleteMaxFileSizeBytes { get; set; } = 1L * 1024L * 1024L * 1024L;
    public long PreDeleteStorageLimitBytes { get; set; } = 2L * 1024L * 1024L * 1024L;

    public string EffectivePreDeleteStorageDirectory
    {
        get
        {
            var path = string.IsNullOrWhiteSpace(PreDeleteStorageDirectory)
                ? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "AlgoLassi",
                    "FileRecovery",
                    "ProtectedStorage")
                : PreDeleteStorageDirectory;

            return Path.GetFullPath(path.Trim());
        }
    }

    public long EffectivePreDeleteMaxFileSizeBytes =>
        Math.Clamp(PreDeleteMaxFileSizeBytes, 1L * 1024L * 1024L, 1024L * 1024L * 1024L * 1024L);

    public long EffectivePreDeleteStorageLimitBytes =>
        Math.Clamp(PreDeleteStorageLimitBytes, 1L * 1024L * 1024L, 4096L * 1024L * 1024L * 1024L);

    public Dictionary<string, VolumeJournalCursor> UsnCursors { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    private static readonly object SaveGate = new();

    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "AlgoLassi",
        "FileRecovery",
        "settings.json");

    public static RecoverySettings Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return new RecoverySettings();
            }

            var settings = JsonSerializer.Deserialize<RecoverySettings>(File.ReadAllText(SettingsPath))
                ?? new RecoverySettings();

            settings.IgnoredDirectories ??= [];
            settings.ProtectedDirectories ??= [];
            settings.UsnCursors ??= new Dictionary<string, VolumeJournalCursor>(StringComparer.OrdinalIgnoreCase);
            return settings;
        }
        catch
        {
            return new RecoverySettings();
        }
    }

    public void Save()
    {
        lock (SaveGate)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
                var temp = SettingsPath + ".tmp";
                File.WriteAllText(temp, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
                File.Move(temp, SettingsPath, overwrite: true);
            }
            catch
            {
                // Settings are non-critical; monitoring should continue if persistence fails.
            }
        }
    }
}

public sealed class VolumeJournalCursor
{
    public ulong JournalId { get; set; }
    public long NextUsn { get; set; }
}
