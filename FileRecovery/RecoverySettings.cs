using System.Text.Json;

namespace FileRecovery;

public sealed class RecoverySettings
{
    public bool NotificationsMuted { get; set; }
    public Dictionary<string, VolumeJournalCursor> UsnCursors { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

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

public sealed class VolumeJournalCursor
{
    public ulong JournalId { get; set; }
    public long NextUsn { get; set; }
}
