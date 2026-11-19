using SkiaSharp;
// Usage: dotnet run --project tools/IconRender -- <output folder>; copy Netcheck.ico and Netcheck-icon-master.png into src/Netcheck/Assets.
// Keep the drawing in step with src/Netcheck/Assets/Netcheck-icon.svg (the editable source).

// Draws src/Netcheck/Assets/Netcheck-icon.svg ("Dusk gauge") with Skia, writes PNGs and a multi-size .ico.
var outDir = args[0];
Directory.CreateDirectory(outDir);
// Gauge size and centre (user, 2026-11-17: it sat ~8 px low and looked small). The gauge's own box (arc top to hub
// bottom, original coords) is centred on (gx, gy) at scale gs. Optional args: <scale> <centre y>.
var gs = args.Length > 1 ? float.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture) : 1.32f;
var gy = args.Length > 2 ? float.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture) : 128f;
const float gx = 128f, boxX = 127f, boxY = 116.15f;   // gauge box centre in original coords (x 47–207, y 67.5–164.8)
SKColor C(string hex, float a = 1) { var c = SKColor.Parse(hex); return c.WithAlpha((byte)Math.Round(a * 255)); }

byte[] Render(int size)
{
    var small = size <= 24;
    using var bmp = new SKBitmap(new SKImageInfo(size, size, SKColorType.Bgra8888, SKAlphaType.Premul));
    using var c = new SKCanvas(bmp);
    c.Clear(SKColors.Transparent);
    c.Scale(size / 256f);
    var tile = new SKRoundRect(new SKRect(4, 4, 252, 252), 56);
    using (var p = new SKPaint { IsAntialias = true })
    {
        p.Shader = SKShader.CreateLinearGradient(new(0, 4), new(0, 252), [C("#2A4472"), C("#1A2C4C"), C("#15243C")], [0, .6f, 1], SKShaderTileMode.Clamp);
        c.DrawRoundRect(tile, p);
        p.Shader = SKShader.CreateRadialGradient(new(128, 4), 198.4f, [C("#2E4A7A", .85f), C("#18294A", 0)], SKShaderTileMode.Clamp);
        c.DrawRoundRect(tile, p);
    }
    // gauge drawn in the original 256 px coordinates, scaled gs and centred on (gx, gy)
    var arcRect = new SKRect(127.5f - 75.5f, 148 - 75.5f, 127.5f + 75.5f, 148 + 75.5f);
    using var lit = new SKPath(); lit.AddArc(arcRect, 171, 158);          // 189° → 31° (maths angles)
    using var dim = new SKPath(); dim.AddArc(arcRect, 329, 39.4f);        // 31° → -8.4°
    var arcWidth = small ? 14f : 10f;
    c.Save(); c.Translate(gx, gy); c.Scale(gs); c.Translate(-boxX, -boxY);
    using (var glow = new SKPaint { IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = 14, StrokeCap = SKStrokeCap.Round,
        Color = C("#8DB8F2", .35f), MaskFilter = SKMaskFilter.CreateBlur(SKBlurStyle.Normal, 5) })
        if (!small) c.DrawPath(lit, glow);
    c.Restore();
    if (!small)
        using (var edge = new SKPaint { IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = 1.5f })
        {
            edge.Shader = SKShader.CreateLinearGradient(new(0, 4), new(0, 252), [C("#FFFFFF", .22f), C("#FFFFFF", .05f), C("#FFFFFF", .03f)], [0, .45f, 1], SKShaderTileMode.Clamp);
            c.DrawRoundRect(new SKRoundRect(new SKRect(4.75f, 4.75f, 251.25f, 251.25f), 55.25f), edge);
        }
    c.Save(); c.Translate(gx, gy); c.Scale(gs); c.Translate(-boxX, -boxY);
    using (var s = new SKPaint { IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = arcWidth, StrokeCap = SKStrokeCap.Round, Color = C("#3E5680") })
        c.DrawPath(dim, s);
    using (var s = new SKPaint { IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = arcWidth, StrokeCap = SKStrokeCap.Round })
    {
        s.Shader = SKShader.CreateLinearGradient(new(53, 160), new(192, 109), [C("#7FA9E6"), C("#D6E7FC")], SKShaderTileMode.Clamp);
        c.DrawPath(lit, s);
    }
    if (!small)
        using (var t = new SKPaint { IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = 4, StrokeCap = SKStrokeCap.Round, Color = C("#7F94B0") })
            foreach (var (x1, y1, x2, y2) in new[] { (180.5f, 137.7f, 187.4f, 136.4f), (162.6f, 106.9f, 167.1f, 101.6f), (127.5f, 94f, 127.5f, 87f),
                                                     (92.4f, 106.9f, 87.9f, 101.6f), (74.5f, 137.7f, 67.6f, 136.4f) })
                c.DrawLine(x1, y1, x2, y2, t);
    // needle (tapered, 43°) and hub; a little bolder at small sizes
    var half = small ? 7f : 4.5f;
    float sx = MathF.Sin(43 * MathF.PI / 180) * half, sy = MathF.Cos(43 * MathF.PI / 180) * half;
    using var needle = new SKPath();
    needle.MoveTo(127.5f - sx, 154 - sy); needle.LineTo(175.8f, 109); needle.LineTo(127.5f + sx, 154 + sy); needle.Close();
    using (var n = new SKPaint { IsAntialias = true, Style = SKPaintStyle.StrokeAndFill, StrokeWidth = 2.5f, StrokeJoin = SKStrokeJoin.Round, Color = C("#E9F0FA") })
    {
        c.DrawPath(needle, n);
        n.Style = SKPaintStyle.Fill;
        c.DrawCircle(127.5f, 154, small ? 13 : 9.5f, n);
    }
    c.Restore();
    using var img = SKImage.FromBitmap(bmp);
    return img.Encode(SKEncodedImageFormat.Png, 100).ToArray();
}

// Every size Windows asks for at 100–250 % scaling (16 × 1.25 = 20, 32 × 1.75 = 56, 48 × 1.5 = 72 …), so the shell never
// stretches a nearby size (that made the Start menu icon look jagged at 175 %, user 2026-11-17).
int[] sizes = [16, 20, 24, 28, 30, 32, 36, 40, 42, 48, 56, 60, 64, 72, 80, 96, 128, 256];
var pngs = sizes.ToDictionary(s => s, Render);
foreach (var (s, data) in pngs) File.WriteAllBytes(Path.Combine(outDir, $"icon-{s}.png"), data);
File.WriteAllBytes(Path.Combine(outDir, "Netcheck-icon-master.png"), Render(512));

using var ico = new BinaryWriter(File.Create(Path.Combine(outDir, "Netcheck.ico")));
ico.Write((ushort)0); ico.Write((ushort)1); ico.Write((ushort)sizes.Length);
var offset = 6 + 16 * sizes.Length;
foreach (var s in sizes)
{
    ico.Write((byte)(s >= 256 ? 0 : s)); ico.Write((byte)(s >= 256 ? 0 : s)); ico.Write((byte)0); ico.Write((byte)0);
    ico.Write((ushort)1); ico.Write((ushort)32); ico.Write(pngs[s].Length); ico.Write(offset);
    offset += pngs[s].Length;
}
foreach (var s in sizes) ico.Write(pngs[s]);
Console.WriteLine($"wrote {sizes.Length} sizes + master to {outDir}");
