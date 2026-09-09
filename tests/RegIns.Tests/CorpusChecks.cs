using RegIns;
using System.Security.Cryptography;
using System.Text.Json;

internal static class CorpusChecks
{
    internal static int Run(string directory, string reportPath)
    {
        byte[] manifestBytes = File.ReadAllBytes(Path.Combine(directory, "manifest.json"));
        string expectedHash = File.ReadAllText(Path.Combine(directory, "manifest.sha256")).Trim();
        if (!Convert.ToHexString(SHA256.HashData(manifestBytes)).Equals(expectedHash, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Frozen manifest changed.");
        using var manifest = JsonDocument.Parse(manifestBytes); var results = new List<object>(); int failures = 0;
        foreach (var spec in manifest.RootElement.GetProperty("cases").EnumerateArray())
        {
            string name = spec.GetProperty("name").GetString()!, path = Path.Combine(directory, spec.GetProperty("file").GetString()!.Replace('\\', Path.DirectorySeparatorChar));
            var errors = new List<string>(); var watch = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                byte[] bytes = File.ReadAllBytes(path);
                if (!Convert.ToHexString(SHA256.HashData(bytes)).Equals(spec.GetProperty("sha256").GetString(), StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Frozen case bytes changed.");
                byte[] mask = Enumerable.Repeat((byte)1, bytes.Length).ToArray();
                foreach (var hole in spec.GetProperty("holes").EnumerateArray()) Array.Clear(mask, hole[0].GetInt32(), hole[1].GetInt32());
                using var source = new MemoryByteSource(bytes, name, mask);
                var options = new RecoveryOptions(HiveBinsOffset: spec.GetProperty("bins_offset").GetInt64());
                if (spec.TryGetProperty("carving_only", out _))
                {
                    var regions = HiveCarver.Scan(source).Where(c => c.Kind == "hive").Select(c => c.Offset).ToArray();
                    foreach (var offset in spec.GetProperty("expected_hive_offsets").EnumerateArray()) if (!regions.Contains(offset.GetInt64())) errors.Add("Missing carved hive at " + offset);
                }
                else
                {
                    var plan = spec.GetProperty("backup_recovery").GetBoolean() ? ArtifactDiscovery.RecoverFile(path, options: options) : Recovery.Plan(new HiveInspector().Inspect(source, options));
                    var inspection = plan.Inspection;
                    foreach (var expected in spec.GetProperty("expected_keys").EnumerateArray()) if (!inspection.Keys.Any(k => k.Name == expected.GetString())) errors.Add("Missing key " + expected);
                    if (spec.GetProperty("expected_keys").GetArrayLength() == 0 && inspection.Keys.Count != 0) errors.Add("Invented records in evidence-free input");
                    foreach (var label in spec.GetProperty("expected_values").EnumerateArray())
                    {
                        var v = manifest.RootElement.GetProperty("values").GetProperty(label.GetString()!); string key = v.GetProperty("key").GetString()!; key = key == "root" ? "ROOT" : char.ToUpperInvariant(key[0]) + key[1..];
                        var actual = inspection.Keys.Where(k => k.Name == key).SelectMany(k => k.Values).FirstOrDefault(x => x.Name == v.GetProperty("name").GetString());
                        byte[] expected = Convert.FromHexString(v.GetProperty("hex").GetString()!);
                        if (actual is null || !actual.Complete || actual.Type != v.GetProperty("type").GetUInt32() || !actual.Extents.OrderBy(e => e.LogicalOffset).SelectMany(e => e.Bytes).SequenceEqual(expected)) errors.Add("Missing/mismatched value " + label);
                    }
                    if (spec.TryGetProperty("expected_parent", out var parents)) foreach (var property in parents.EnumerateObject()) { var key = inspection.Keys.FirstOrDefault(k => k.Name == property.Name); if (key is null || !inspection.Keys.Any(p => p.Name == property.Value.GetString() && p.Offset == plan.ParentOverrides.GetValueOrDefault(key.Offset, key.ParentOffset))) errors.Add("Missing reconstructed parent for " + property.Name); }
                    if (spec.TryGetProperty("expected_unowned", out var unowned)) foreach (var v in unowned.EnumerateArray()) if (!inspection.UnownedValues.Any(x => x.Name == v.GetString())) errors.Add("Missing unowned evidence " + v);
                    if (spec.TryGetProperty("expected_partial_value", out var partialName)) { var v = inspection.Keys.SelectMany(k => k.Values).FirstOrDefault(v => v.Name == partialName.GetString()); if (v is null || v.Complete || v.Extents.Sum(e => e.Bytes.Length) != spec.GetProperty("expected_readable_bytes").GetInt32()) errors.Add("Partial extents incorrect"); }
                    if (spec.TryGetProperty("expected_binary_zero_run", out var zeros)) { var v = inspection.Keys.SelectMany(k => k.Values).Single(v => v.Name == "Bytes"); byte[] data = v.Extents.SelectMany(e => e.Bytes).ToArray(); if (!v.Complete || !data.AsSpan(zeros[0].GetInt32(),zeros[1].GetInt32()).SequenceEqual(new byte[zeros[1].GetInt32()])) errors.Add("Readable zeroes misclassified"); }
                    if (spec.TryGetProperty("expected_carved_hive", out var carved) && !HiveCarver.Scan(source).Any(c => c.Kind == "hive" && c.Offset == carved.GetInt64())) errors.Add("Misaligned hive not carved");
                    if (plan.Candidates.Count > 0 && spec.GetProperty("known_loss").GetArrayLength() == 0)
                    {
                        bool replace = spec.TryGetProperty("export_requires_security_replacement", out _);
                        try { var output = HiveWriter.Export(plan, new(replace)); if (output.Report.KeysWritten < spec.GetProperty("expected_keys").GetArrayLength()) errors.Add("Selected export omitted recoverable keys"); }
                        catch (Exception e) { errors.Add("Export: " + e.Message); }
                    }
                }
                if (!SHA256.HashData(bytes).SequenceEqual(SHA256.HashData(File.ReadAllBytes(path)))) errors.Add("Input mutated");
            }
            catch (Exception e) { errors.Add(e.GetType().Name + ": " + e.Message); }
            if (errors.Count > 0) failures++;
            results.Add(new { name, passed = errors.Count == 0, elapsedMs = watch.ElapsedMilliseconds, errors });
            Console.WriteLine($"{(errors.Count == 0 ? "PASS" : "FAIL")} {name}" + (errors.Count == 0 ? "" : ": " + string.Join("; ",errors)));
        }
        File.WriteAllText(reportPath, JsonSerializer.Serialize(new { manifestSha256 = expectedHash, cases = results.Count, failures, results },new JsonSerializerOptions { WriteIndented = true }));
        return failures;
    }
}
