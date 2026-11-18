using System.Text;

namespace Majorsilence.Banish.Detectors;

/// <summary>Reads new complete lines appended to a file, surviving truncation and rotation.</summary>
public sealed class TailedFile : IDisposable
{
    private readonly string _path;
    private readonly Decoder _decoder = new UTF8Encoding(false).GetDecoder();
    private readonly StringBuilder _partial = new();
    private FileStream? _stream;
    private long _position;
    private bool _first = true;
    private readonly bool _fromStart;

    public TailedFile(string path, bool fromStart)
    {
        _path = path;
        _fromStart = fromStart;
    }

    public string Path => _path;

    /// <summary>Reads whatever was appended since the last call and returns the complete lines.</summary>
    public IReadOnlyList<string> ReadNewLines()
    {
        var lines = new List<string>();
        try
        {
            var info = new FileInfo(_path);
            if (!info.Exists)
            {
                CloseStream();
                return lines;
            }

            if (_stream is null)
            {
                _stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                // After a rotation the new file is read from its start; the very first open honours fromStart.
                _position = _first && !_fromStart ? _stream.Length : 0;
                _first = false;
                _stream.Seek(_position, SeekOrigin.Begin);
            }

            if (_stream.Length < _position)
            {
                // Truncated in place.
                _position = 0;
                _partial.Clear();
                _stream.Seek(0, SeekOrigin.Begin);
            }
            else if (info.Length < _position)
            {
                // Replaced by a shorter file (rotation): start over on the new file.
                CloseStream();
                _partial.Clear();
                return lines;
            }

            var bytes = new byte[8192];
            var chars = new char[8192];
            int read;
            while ((read = _stream.Read(bytes, 0, bytes.Length)) > 0)
            {
                _position += read;
                int count = _decoder.GetChars(bytes, 0, read, chars, 0);
                for (int i = 0; i < count; i++)
                {
                    char c = chars[i];
                    if (c == '\n')
                    {
                        if (_partial.Length > 0 && _partial[^1] == '\r')
                        {
                            _partial.Length--;
                        }

                        lines.Add(_partial.ToString());
                        _partial.Clear();
                    }
                    else if (_partial.Length < 64 * 1024)
                    {
                        _partial.Append(c);
                    }
                }
            }
        }
        catch (IOException)
        {
            CloseStream();
        }
        catch (UnauthorizedAccessException)
        {
            CloseStream();
        }

        return lines;
    }

    public void Dispose() => CloseStream();

    private void CloseStream()
    {
        _stream?.Dispose();
        _stream = null;
    }
}
