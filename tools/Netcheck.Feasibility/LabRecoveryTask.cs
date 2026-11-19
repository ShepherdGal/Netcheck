using System.Globalization;
using System.Runtime.Versioning;

internal interface ILabRecoveryTask
{
    bool Exists();
    void Register();
    void Remove();
}

[SupportedOSPlatform("windows")]
internal sealed class LabRecoveryTask : ILabRecoveryTask
{
    private const string Name = "Netcheck.Feasibility.RestoreDns";
    private const string SystemAccount = "S-1-5-18";
    private const int TaskNotFound = unchecked((int)0x80070002);
    private readonly dynamic _service;
    private readonly dynamic _root;
    private readonly string _installedExecutable;

    internal LabRecoveryTask(string installedExecutable)
    {
        _installedExecutable = installedExecutable;
        var serviceType = Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!;
        _service = Activator.CreateInstance(serviceType)!;
        _service.Connect();
        _root = _service.GetFolder(@"\");
    }

    public bool Exists()
    {
        try
        {
            _root.GetTask(Name);
            return true;
        }
        catch (Exception error) when (error.HResult == TaskNotFound)
        {
            return false;
        }
    }

    public void Register()
    {
        const int timeTrigger = 1;
        const int bootTrigger = 8;
        const int executableAction = 0;
        const int createOnly = 2;
        const int serviceAccountLogon = 5;
        const int highestRunLevel = 1;

        dynamic definition = _service.NewTask(0);
        definition.RegistrationInfo.Description = "Restores DNS on the Netcheck VM lab adapter.";
        definition.Principal.UserId = SystemAccount;
        definition.Principal.LogonType = serviceAccountLogon;
        definition.Principal.RunLevel = highestRunLevel;
        definition.Settings.StartWhenAvailable = true;
        definition.Settings.DisallowStartIfOnBatteries = false;
        definition.Settings.StopIfGoingOnBatteries = false;
        definition.Settings.ExecutionTimeLimit = "PT2M";
        definition.Settings.RestartInterval = "PT1M";
        definition.Settings.RestartCount = 3;
        dynamic deadline = definition.Triggers.Create(timeTrigger);
        deadline.StartBoundary = DateTimeOffset.UtcNow.AddMinutes(5)
            .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        definition.Triggers.Create(bootTrigger);
        dynamic action = definition.Actions.Create(executableAction);
        action.Path = _installedExecutable;
        action.Arguments = "dns-recover";
        action.WorkingDirectory = Path.GetDirectoryName(_installedExecutable);
        _root.RegisterTaskDefinition(Name, definition, createOnly, SystemAccount, null, serviceAccountLogon, null);
    }

    public void Remove()
    {
        if (Exists())
        {
            _root.DeleteTask(Name, 0);
        }
    }
}
