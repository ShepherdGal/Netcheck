namespace Netcheck.Windows;

public static class NetcheckInstance
{
    // Keep this Windows-wide identity stable across application upgrades.
    private const string MutexName = @"Global\Netcheck.Desktop.14D6E4D7-2443-46C8-85BB-73D87D073305";

    public static Mutex? TryAcquire(TimeSpan wait = default)
    {
        Mutex mutex;
        try { mutex = new Mutex(false, MutexName); }
        catch (UnauthorizedAccessException)
        {
            // The running instance may belong to a different Windows account.
            return null;
        }

        try
        {
            if (mutex.WaitOne(wait))
                return mutex;
        }
        catch (AbandonedMutexException)
        {
            // Windows granted ownership after the previous process exited unexpectedly.
            return mutex;
        }

        mutex.Dispose();
        return null;
    }
}

