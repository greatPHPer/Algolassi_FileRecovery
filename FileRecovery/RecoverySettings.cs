using System.Text.Json;

namespace FileRecovery;

public sealed class RecoverySettings
{
    public bool NotificationsMuted { get; set; }

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

            return JsonSerializer.Deserialize<RecoverySettings>(File.ReadAllText(SettingsPath))
                ?? new RecoverySettings();
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
