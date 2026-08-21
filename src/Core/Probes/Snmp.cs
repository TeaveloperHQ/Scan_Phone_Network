using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ScanPhoneNetwork.Probes;

/// <summary>
/// SNMP v2c 최소 구현. GET / GETNEXT 와 테이블 워크만 한다.
///
/// <para>
/// 기존 <see cref="SnmpProbe"/> 는 sysDescr 하나를 읽으려고 BER 패킷을 통째로 하드코딩해
/// 뒀는데, 그 방식으로는 OID 를 바꿔 가며 훑는 테이블 워크를 할 수 없다.
/// 스위치의 MAC 주소 테이블(FDB)을 읽으려면 GETNEXT 를 반복해야 하므로
/// BER 인코더·디코더가 필요하다.
/// </para>
///
/// <para>외부 라이브러리를 쓰지 않는다. 배포가 exe 하나여야 하기 때문이다.</para>
/// </summary>
public static class Snmp
{
    public const byte TypeInteger = 0x02;
    public const byte TypeOctetString = 0x04;
    public const byte TypeNull = 0x05;
    public const byte TypeOid = 0x06;
    public const byte TypeSequence = 0x30;
    public const byte TypeGetNextRequest = 0xA1;
    public const byte TypeGetResponse = 0xA2;

    /// <summary>워크가 테이블 끝에 닿았을 때 오는 표식들.</summary>
    private const byte EndOfMibView = 0x82;
    private const byte NoSuchObject = 0x80;
    private const byte NoSuchInstance = 0x81;

    public sealed record VarBind(int[] Oid, byte Type, byte[] Value)
    {
        public long AsLong()
        {
            long v = 0;
            foreach (var b in Value) v = (v << 8) | b;
            return v;
        }

        public string AsString() => Encoding.UTF8.GetString(Value).Trim('\0', ' ');
    }

    // ------------------------------------------------------------------
    // 워크
    // ------------------------------------------------------------------

    /// <summary>
    /// rootOid 아래를 GETNEXT 로 훑는다. 돌아온 OID 가 rootOid 로 시작하지 않으면 테이블 끝이다.
    /// </summary>
    /// <param name="maxRows">폭주 방지 상한. 스위치 FDB 는 수천 줄이 될 수 있다.</param>
    public static async Task<List<VarBind>> WalkAsync(
        IPAddress ip, string community, int[] rootOid,
        int timeoutMs = 1500, int maxRows = 4096, CancellationToken ct = default)
    {
        var rows = new List<VarBind>();
        int[] cur = rootOid;
        int requestId = 1;

        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.ReceiveTimeout = timeoutMs;

        while (rows.Count < maxRows && !ct.IsCancellationRequested)
        {
            byte[] req = BuildGetNext(community, cur, requestId++);
            VarBind? vb;
            try
            {
                await udp.SendAsync(req, req.Length, new IPEndPoint(ip, 161));
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeoutMs);
                var res = await udp.ReceiveAsync(cts.Token);
                vb = ParseFirstVarBind(res.Buffer);
            }
            catch { break; }   // 무응답·형식오류 = 여기까지

            if (vb is null) break;
            if (vb.Type is EndOfMibView or NoSuchObject or NoSuchInstance) break;
            if (!StartsWith(vb.Oid, rootOid)) break;   // 테이블 밖으로 나갔다
            if (SameOid(vb.Oid, cur)) break;           // 안 움직이면 무한루프

            rows.Add(vb);
            cur = vb.Oid;
        }
        return rows;
    }

    /// <summary>장비가 이 community 로 SNMP 에 답하는지 빠르게 확인(sysDescr).</summary>
    public static async Task<string?> ProbeAsync(
        IPAddress ip, string community, int timeoutMs = 1200, CancellationToken ct = default)
    {
        // sysDescr 는 1.3.6.1.2.1.1.1, 그 아래 .0 을 GETNEXT 로 집는다
        var rows = await WalkAsync(ip, community, new[] { 1, 3, 6, 1, 2, 1, 1, 1 },
                                   timeoutMs, maxRows: 1, ct);
        return rows.Count > 0 ? rows[0].AsString() : null;
    }

    // ------------------------------------------------------------------
    // 인코딩
    // ------------------------------------------------------------------

    /// <summary>
    /// 응답 패킷을 만든다. 실제 통신에는 쓰지 않고 <b>인코더·디코더 검증용</b>이다.
    /// 스위치 SNMP 가 막혀 있는 환경에서도 BER 처리가 맞는지 확인할 수 있어야 한다
    /// (OID 마디가 127 을 넘는 경우, 길이가 127 바이트를 넘는 경우 등이 버그가 숨는 자리다).
    /// </summary>
    public static byte[] BuildResponse(string community, int[] oid, byte valueType, byte[] value, int requestId = 1)
    {
        var varbind = Tlv(TypeSequence, Concat(EncodeOid(oid), Tlv(valueType, value)));
        var pdu = Tlv(TypeGetResponse, Concat(
            Tlv(TypeInteger, EncodeInt(requestId)),
            Tlv(TypeInteger, EncodeInt(0)),
            Tlv(TypeInteger, EncodeInt(0)),
            Tlv(TypeSequence, varbind)));
        return Tlv(TypeSequence, Concat(
            Tlv(TypeInteger, EncodeInt(1)),
            Tlv(TypeOctetString, Encoding.ASCII.GetBytes(community)),
            pdu));
    }

    private static byte[] BuildGetNext(string community, int[] oid, int requestId)
    {
        var varbind = Tlv(TypeSequence, Concat(EncodeOid(oid), Tlv(TypeNull, Array.Empty<byte>())));
        var varbindList = Tlv(TypeSequence, varbind);

        var pdu = Tlv(TypeGetNextRequest, Concat(
            Tlv(TypeInteger, EncodeInt(requestId)),
            Tlv(TypeInteger, EncodeInt(0)),   // error-status
            Tlv(TypeInteger, EncodeInt(0)),   // error-index
            varbindList));

        return Tlv(TypeSequence, Concat(
            Tlv(TypeInteger, EncodeInt(1)),   // version 1 = SNMPv2c
            Tlv(TypeOctetString, Encoding.ASCII.GetBytes(community)),
            pdu));
    }

    private static byte[] EncodeOid(int[] oid)
    {
        var body = new List<byte> { (byte)(oid[0] * 40 + oid[1]) };
        for (int i = 2; i < oid.Length; i++) body.AddRange(Base128(oid[i]));
        return Tlv(TypeOid, body.ToArray());
    }

    /// <summary>OID 의 각 마디는 7비트씩 끊어 담고, 마지막 바이트만 최상위 비트가 0 이다.</summary>
    private static byte[] Base128(int value)
    {
        if (value == 0) return new byte[] { 0 };
        var stack = new Stack<byte>();
        stack.Push((byte)(value & 0x7F));
        value >>= 7;
        while (value > 0)
        {
            stack.Push((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }
        return stack.ToArray();
    }

    private static byte[] EncodeInt(long value)
    {
        var bytes = new List<byte>();
        bool negative = value < 0;
        do
        {
            bytes.Insert(0, (byte)(value & 0xFF));
            value >>= 8;
        } while (value != 0 && value != -1);

        // 부호 비트가 값의 일부로 읽히지 않도록 한 바이트 덧댄다
        if (!negative && (bytes[0] & 0x80) != 0) bytes.Insert(0, 0x00);
        if (negative && (bytes[0] & 0x80) == 0) bytes.Insert(0, 0xFF);
        return bytes.ToArray();
    }

    private static byte[] Tlv(byte type, params byte[][] parts) => Tlv(type, Concat(parts));

    private static byte[] Tlv(byte type, byte[] body)
    {
        var len = EncodeLength(body.Length);
        var res = new byte[1 + len.Length + body.Length];
        res[0] = type;
        Array.Copy(len, 0, res, 1, len.Length);
        Array.Copy(body, 0, res, 1 + len.Length, body.Length);
        return res;
    }

    private static byte[] EncodeLength(int len)
    {
        if (len < 0x80) return new[] { (byte)len };
        var tmp = new List<byte>();
        int v = len;
        while (v > 0) { tmp.Insert(0, (byte)(v & 0xFF)); v >>= 8; }
        tmp.Insert(0, (byte)(0x80 | tmp.Count));
        return tmp.ToArray();
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int n = parts.Sum(p => p.Length);
        var res = new byte[n];
        int o = 0;
        foreach (var p in parts) { Array.Copy(p, 0, res, o, p.Length); o += p.Length; }
        return res;
    }

    // ------------------------------------------------------------------
    // 디코딩
    // ------------------------------------------------------------------

    /// <summary>응답에서 첫 번째 varbind 를 꺼낸다. GETNEXT 는 하나만 요청하므로 그거면 된다.</summary>
    public static VarBind? ParseFirstVarBind(byte[] buf)
    {
        int p = 0;
        if (!ReadTlv(buf, ref p, out byte t, out int len) || t != TypeSequence) return null;
        int end = p + len;

        if (!SkipTlv(buf, ref p, end)) return null;   // version
        if (!SkipTlv(buf, ref p, end)) return null;   // community

        if (!ReadTlv(buf, ref p, out t, out len)) return null;   // PDU
        if (t != TypeGetResponse) return null;
        end = p + len;

        if (!SkipTlv(buf, ref p, end)) return null;   // request-id
        if (!SkipTlv(buf, ref p, end)) return null;   // error-status
        if (!SkipTlv(buf, ref p, end)) return null;   // error-index

        if (!ReadTlv(buf, ref p, out t, out len) || t != TypeSequence) return null;  // varbind list
        end = p + len;
        if (!ReadTlv(buf, ref p, out t, out len) || t != TypeSequence) return null;  // varbind
        end = p + len;

        if (!ReadTlv(buf, ref p, out t, out len) || t != TypeOid) return null;
        var oid = DecodeOid(buf, p, len);
        p += len;

        if (!ReadTlv(buf, ref p, out byte vt, out int vlen)) return null;
        if (p + vlen > buf.Length) vlen = Math.Max(0, buf.Length - p);
        var val = new byte[vlen];
        Array.Copy(buf, p, val, 0, vlen);
        return new VarBind(oid, vt, val);
    }

    private static int[] DecodeOid(byte[] buf, int p, int len)
    {
        var arcs = new List<int>();
        int end = p + len;
        if (p < end)
        {
            arcs.Add(buf[p] / 40);
            arcs.Add(buf[p] % 40);
            p++;
        }
        int cur = 0;
        while (p < end)
        {
            cur = (cur << 7) | (buf[p] & 0x7F);
            if ((buf[p] & 0x80) == 0) { arcs.Add(cur); cur = 0; }
            p++;
        }
        return arcs.ToArray();
    }

    private static bool ReadTlv(byte[] buf, ref int p, out byte type, out int len)
    {
        type = 0; len = 0;
        if (p + 2 > buf.Length) return false;
        type = buf[p++];
        int l = buf[p++];
        if ((l & 0x80) != 0)
        {
            int n = l & 0x7F;
            if (n == 0 || p + n > buf.Length) return false;
            l = 0;
            for (int i = 0; i < n; i++) l = (l << 8) | buf[p++];
        }
        len = l;
        return p + len <= buf.Length;
    }

    private static bool SkipTlv(byte[] buf, ref int p, int end)
    {
        if (!ReadTlv(buf, ref p, out _, out int len)) return false;
        p += len;
        return p <= end;
    }

    public static bool StartsWith(int[] oid, int[] prefix)
    {
        if (oid.Length < prefix.Length) return false;
        for (int i = 0; i < prefix.Length; i++) if (oid[i] != prefix[i]) return false;
        return true;
    }

    private static bool SameOid(int[] a, int[] b) =>
        a.Length == b.Length && !a.Where((t, i) => t != b[i]).Any();
}
