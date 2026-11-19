using Netcheck.Core;

namespace Netcheck.Measurements;

public static class RepeatedHttpsTest
{
    public const int RunCount = 3;
    public const int RunDeadlineSeconds = 55;

    public static async Task<MeasurementResult> RunAsync(MeasurementOptions options,
        Func<MeasurementOptions, CancellationToken, Task<MeasurementResult>> run,
        Func<bool> canContinue, CancellationToken token)
    {
        if (options.Mode != MeasurementMode.Thorough || options.SustainedDuration is null ||
            options.Duration <= TimeSpan.Zero || options.Duration > TimeSpan.FromSeconds(RunDeadlineSeconds) ||
            options.PayloadBudget < 2L * RunCount * MeasurementProtocol.MiB ||
            options.PayloadBudget > MeasurementProtocol.SustainedBudgetLimit)
            throw new ArgumentException("Invalid sustained repeat configuration.", nameof(options));

        var started = DateTimeOffset.UtcNow;
        var results = new List<MeasurementResult>(RunCount);
        var notes = new List<string>();
        for (var index = 0; index < RunCount && !token.IsCancellationRequested; index++)
        {
            if (!canContinue())
            {
                notes.Add("Connection cost changed. Review the traffic allowance before starting another test.");
                break;
            }
            var allowance = options.PayloadBudget / RunCount + (index < options.PayloadBudget % RunCount ? 1 : 0);
            MeasurementResult result;
            try
            {
                result = await run(options with { Mode = MeasurementMode.Standard, PayloadBudget = allowance }, token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                break;
            }
            results.Add(result);
            if (result.State != MeasurementState.Complete)
            {
                notes.Add($"Run {index + 1} ended with {result.State.ToString().ToLowerInvariant()} results. The remaining runs were skipped.");
                break;
            }
            if (!result.Paths.ToHashSet().SetEquals(results[0].Paths) || result.Endpoint != results[0].Endpoint)
            {
                notes.Add("The endpoint or observed route changed between runs. The results cannot be combined.");
                break;
            }
        }
        var state = results.Count == RunCount && notes.Count == 0 ? MeasurementState.Complete :
            token.IsCancellationRequested ? MeasurementState.Stopped :
            results.Count == 1 && results[0].State is MeasurementState.Failed or MeasurementState.TimedOut
                ? results[0].State : MeasurementState.Partial;
        var first = results.FirstOrDefault();
        return new MeasurementResult(options with { Duration = options.Duration * RunCount }, started, DateTimeOffset.UtcNow, state, first?.Endpoint,
            results.SelectMany(result => result.Paths).Distinct().ToArray(), results.Sum(result => result.PayloadBytes),
            null, null, null, [], notes.ToArray(), ProviderVersion: first?.ProviderVersion)
        {
            Repeats = results.ToArray(),
            PlannedRuns = RunCount
        };
    }
}
