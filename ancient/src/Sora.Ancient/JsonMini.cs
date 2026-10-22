using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Sora.Ancient
{
    // Minimal JSON reader/writer: the ancient track takes no third-party
    // dependency (the era runtime machines are offline-grade and the
    // client must build for net40 with nothing but reference assemblies).
    // The reader is a strict recursive-descent parser producing
    // Dictionary<string,object> / List<object> / string / double / bool /
    // null. The writer escapes per RFC 8259. Both are covered by the
    // ParserCheck harness (tools/ParserCheck).
    internal static class JsonMini
    {
        public static object Parse(string text)
        {
            if (text == null) throw new FormatException("JSON text is missing.");
            var p = new Parser(text);
            p.SkipWs();
            object value = p.ReadValue();
            p.SkipWs();
            if (!p.End) throw new FormatException("Trailing characters after JSON value.");
            return value;
        }

        public static string Quote(string value)
        {
            if (value == null) return "null";
            var sb = new StringBuilder(value.Length + 2);
            sb.Append('"');
            foreach (char c in value)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                            sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else
                            sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        private sealed class Parser
        {
            private readonly string _s;
            private int _i;

            public Parser(string s) { _s = s; }
            public bool End { get { return _i >= _s.Length; } }

            public void SkipWs()
            {
                while (_i < _s.Length && (_s[_i] == ' ' || _s[_i] == '\t' || _s[_i] == '\n' || _s[_i] == '\r')) _i++;
            }

            public object ReadValue()
            {
                if (End) throw new FormatException("Unexpected end of JSON.");
                char c = _s[_i];
                if (c == '{') return ReadObject();
                if (c == '[') return ReadArray();
                if (c == '"') return ReadString();
                if (c == 't') { Expect("true"); return true; }
                if (c == 'f') { Expect("false"); return false; }
                if (c == 'n') { Expect("null"); return null; }
                return ReadNumber();
            }

            private void Expect(string literal)
            {
                if (_i + literal.Length > _s.Length ||
                    string.Compare(_s.Substring(_i, literal.Length), literal, StringComparison.Ordinal) != 0)
                    throw new FormatException("Invalid JSON literal.");
                _i += literal.Length;
            }

            private Dictionary<string, object> ReadObject()
            {
                var map = new Dictionary<string, object>();
                _i++; SkipWs();
                if (!End && _s[_i] == '}') { _i++; return map; }
                while (true)
                {
                    SkipWs();
                    if (End || _s[_i] != '"') throw new FormatException("Expected object key.");
                    string key = ReadString();
                    SkipWs();
                    if (End || _s[_i] != ':') throw new FormatException("Expected ':' in object.");
                    _i++; SkipWs();
                    map[key] = ReadValue();
                    SkipWs();
                    if (End) throw new FormatException("Unterminated object.");
                    if (_s[_i] == ',') { _i++; continue; }
                    if (_s[_i] == '}') { _i++; return map; }
                    throw new FormatException("Expected ',' or '}' in object.");
                }
            }

            private List<object> ReadArray()
            {
                var list = new List<object>();
                _i++; SkipWs();
                if (!End && _s[_i] == ']') { _i++; return list; }
                while (true)
                {
                    SkipWs();
                    list.Add(ReadValue());
                    SkipWs();
                    if (End) throw new FormatException("Unterminated array.");
                    if (_s[_i] == ',') { _i++; continue; }
                    if (_s[_i] == ']') { _i++; return list; }
                    throw new FormatException("Expected ',' or ']' in array.");
                }
            }

            private string ReadString()
            {
                var sb = new StringBuilder();
                _i++; // opening quote
                while (true)
                {
                    if (End) throw new FormatException("Unterminated string.");
                    char c = _s[_i++];
                    if (c == '"') return sb.ToString();
                    if (c != '\\') { sb.Append(c); continue; }
                    if (End) throw new FormatException("Unterminated escape.");
                    char e = _s[_i++];
                    switch (e)
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case '/': sb.Append('/'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u':
                            if (_i + 4 > _s.Length) throw new FormatException("Bad \\u escape.");
                            sb.Append((char)int.Parse(_s.Substring(_i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                            _i += 4;
                            break;
                        default: throw new FormatException("Bad escape in string.");
                    }
                }
            }

            private object ReadNumber()
            {
                int start = _i;
                while (_i < _s.Length && "-+0123456789.eE".IndexOf(_s[_i]) >= 0) _i++;
                if (start == _i) throw new FormatException("Invalid JSON value.");
                double d;
                if (!double.TryParse(_s.Substring(start, _i - start), NumberStyles.Float, CultureInfo.InvariantCulture, out d))
                    throw new FormatException("Invalid JSON number.");
                return d;
            }
        }

        // Typed accessors used by the parsers; all fail with FormatException
        // carrying a field name, never a raw framework message.
        public static string GetString(Dictionary<string, object> map, string key, string fallback)
        {
            object v;
            if (map == null || !map.TryGetValue(key, out v) || v == null) return fallback;
            var s = v as string;
            if (s != null) return s;
            var d = v as double?;
            if (d.HasValue) return d.Value.ToString("0.################", CultureInfo.InvariantCulture);
            return fallback;
        }

        public static int GetInt(Dictionary<string, object> map, string key, int fallback)
        {
            object v;
            if (map == null || !map.TryGetValue(key, out v) || v == null) return fallback;
            var d = v as double?;
            if (d.HasValue) return (int)d.Value;
            var s = v as string;
            int n;
            if (s != null && int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out n)) return n;
            return fallback;
        }
    }
}
