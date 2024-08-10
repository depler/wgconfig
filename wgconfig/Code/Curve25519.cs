//based on https://github.com/hanswolff/curve25519

using System;
using System.Security.Cryptography;

namespace Wireguard.Code
{
    public static class Curve25519
    {
        private class Long10
        {
            public long N0, N1, N2, N3, N4, N5, N6, N7, N8, N9;
        }

        public static readonly int KeySize = 32;
        private static readonly int P25 = 0x01FFFFFF;
        private static readonly int P26 = 0x03FFFFFF;

        public static string GetPresharedKey()
        {
            var key = GetRandomBytes();
            return Convert.ToBase64String(key);
        }

        public static string GetPrivateKey()
        {
            var key = GetRandomBytes();
            Clamp(key);

            return Convert.ToBase64String(key);
        }

        public static string GetPublicKey(string privateKey)
        {
            var privateKeyRaw = Convert.FromBase64String(privateKey);
            if (privateKeyRaw.Length != KeySize)
                throw new ArgumentOutOfRangeException(nameof(privateKey));

            var dx = new Long10();
            var x = new[] { new Long10(), new Long10() };
            var z = new[] { new Long10(), new Long10() };

            Set(dx, 9);
            Set(x[0], 1);
            Set(z[0], 0);
            Copy(x[1], dx);
            Set(z[1], 1);

            var t1 = new Long10();
            var t2 = new Long10();
            var t3 = new Long10();
            var t4 = new Long10();

            for (int i = 32; i-- != 0;)
                for (int j = 8; j-- != 0;)
                {
                    int bit1 = (privateKeyRaw[i] & 0xFF) >> j & 1;
                    int bit0 = ~(privateKeyRaw[i] & 0xFF) >> j & 1;

                    var ax = x[bit0];
                    var az = z[bit0];
                    var bx = x[bit1];
                    var bz = z[bit1];

                    MontyPrepare(t1, t2, ax, az);
                    MontyPrepare(t3, t4, bx, bz);
                    MontyAdd(t1, t2, t3, t4, ax, az, dx);
                    MontyDouble(t1, t2, t3, t4, bx, bz);
                }

            Reciprocal(t1, z[0]);
            Multiply(dx, x[0], t1);

            var publicKeyRaw = Pack(dx);
            return Convert.ToBase64String(publicKeyRaw);
        }

        static void Reciprocal(Long10 value, Long10 x)
        {
            var t0 = new Long10();
            var t1 = new Long10();
            var t2 = new Long10();
            var t3 = new Long10();
            var t4 = new Long10();

            Square(t1, x);
            Square(t2, t1);
            Square(t0, t2);
            Multiply(t2, t0, x);
            Multiply(t0, t2, t1);
            Square(t1, t0);
            Multiply(t3, t1, t2);
            Square(t1, t3);
            Square(t2, t1);
            Square(t1, t2);
            Square(t2, t1);
            Square(t1, t2);
            Multiply(t2, t1, t3);
            Square(t1, t2);
            Square(t3, t1);

            for (int i = 1; i < 5; i++)
            {
                Square(t1, t3);
                Square(t3, t1);
            }

            Multiply(t1, t3, t2);
            Square(t3, t1);
            Square(t4, t3);

            for (int i = 1; i < 10; i++)
            {
                Square(t3, t4);
                Square(t4, t3);
            }

            Multiply(t3, t4, t1);

            for (int i = 0; i < 5; i++)
            {
                Square(t1, t3);
                Square(t3, t1);
            }

            Multiply(t1, t3, t2);
            Square(t2, t1);
            Square(t3, t2);

            for (int i = 1; i < 25; i++)
            {
                Square(t2, t3);
                Square(t3, t2);
            }

            Multiply(t2, t3, t1);
            Square(t3, t2);
            Square(t4, t3);

            for (int i = 1; i < 50; i++)
            {
                Square(t3, t4);
                Square(t4, t3);
            }

            Multiply(t3, t4, t2);

            for (int i = 0; i < 25; i++)
            {
                Square(t4, t3);
                Square(t3, t4);
            }

            Multiply(t2, t3, t1);
            Square(t1, t2);
            Square(t2, t1);

            Square(t1, t2);
            Square(t2, t1);
            Square(t1, t2);
            Multiply(value, t1, t0);
        }

        private static void MontyPrepare(Long10 t1, Long10 t2, Long10 ax, Long10 az)
        {
            Add(t1, ax, az);
            Sub(t2, ax, az);
        }

        private static void MontyAdd(Long10 t1, Long10 t2, Long10 t3, Long10 t4, Long10 ax, Long10 az, Long10 dx)
        {
            Multiply(ax, t2, t3);
            Multiply(az, t1, t4);
            Add(t1, ax, az);
            Sub(t2, ax, az);
            Square(ax, t1);
            Square(t1, t2);
            Multiply(az, t1, dx);
        }

        private static void MontyDouble(Long10 t1, Long10 t2, Long10 t3, Long10 t4, Long10 bx, Long10 bz)
        {
            Square(t1, t3);
            Square(t2, t4);
            Multiply(bx, t1, t2);
            Sub(t2, t1, t2);
            MulSmall(bz, t2, 121665);
            Add(t1, t1, bz);
            Multiply(bz, t1, t2);
        }

        private static void MulSmall(Long10 value, Long10 x, long y)
        {
            long temp = (x.N8 * y);
            value.N8 = (temp & ((1 << 26) - 1));

            temp = (temp >> 26) + (x.N9 * y);
            value.N9 = (temp & ((1 << 25) - 1));

            temp = 19 * (temp >> 25) + (x.N0 * y);
            value.N0 = (temp & ((1 << 26) - 1));

            temp = (temp >> 26) + (x.N1 * y);
            value.N1 = (temp & ((1 << 25) - 1));

            temp = (temp >> 25) + (x.N2 * y);
            value.N2 = (temp & ((1 << 26) - 1));

            temp = (temp >> 26) + (x.N3 * y);
            value.N3 = (temp & ((1 << 25) - 1));

            temp = (temp >> 25) + (x.N4 * y);
            value.N4 = (temp & ((1 << 26) - 1));

            temp = (temp >> 26) + (x.N5 * y);
            value.N5 = (temp & ((1 << 25) - 1));

            temp = (temp >> 25) + (x.N6 * y);
            value.N6 = (temp & ((1 << 26) - 1));

            temp = (temp >> 26) + (x.N7 * y);
            value.N7 = (temp & ((1 << 25) - 1));

            temp = (temp >> 25) + value.N8;
            value.N8 = (temp & ((1 << 26) - 1));
            value.N9 += (temp >> 26);
        }

        private static void Square(Long10 value, Long10 x)
        {
            long
                x0 = x.N0,
                x1 = x.N1,
                x2 = x.N2,
                x3 = x.N3,
                x4 = x.N4,
                x5 = x.N5,
                x6 = x.N6,
                x7 = x.N7,
                x8 = x.N8,
                x9 = x.N9;

            long t = (x4 * x4) + 2 * ((x0 * x8) + (x2 * x6)) + 38 * (x9 * x9) + 4 * ((x1 * x7) + (x3 * x5));
            value.N8 = (t & ((1 << 26) - 1));

            t = (t >> 26) + 2 * ((x0 * x9) + (x1 * x8) + (x2 * x7) + (x3 * x6) + (x4 * x5));
            value.N9 = (t & ((1 << 25) - 1));

            t = 19 * (t >> 25) + (x0 * x0) + 38 * ((x2 * x8) + (x4 * x6) + (x5 * x5)) + 76 * ((x1 * x9) + (x3 * x7));
            value.N0 = (t & ((1 << 26) - 1));

            t = (t >> 26) + 2 * (x0 * x1) + 38 * ((x2 * x9) + (x3 * x8) + (x4 * x7) + (x5 * x6));
            value.N1 = (t & ((1 << 25) - 1));

            t = (t >> 25) + 19 * (x6 * x6) + 2 * ((x0 * x2) + (x1 * x1)) + 38 * (x4 * x8) + 76 * ((x3 * x9) + (x5 * x7));
            value.N2 = (t & ((1 << 26) - 1));

            t = (t >> 26) + 2 * ((x0 * x3) + (x1 * x2)) + 38 * ((x4 * x9) + (x5 * x8) + (x6 * x7));
            value.N3 = (t & ((1 << 25) - 1));

            t = (t >> 25) + (x2 * x2) + 2 * (x0 * x4) + 38 * ((x6 * x8) + (x7 * x7)) + 4 * (x1 * x3) + 76 * (x5 * x9);
            value.N4 = (t & ((1 << 26) - 1));

            t = (t >> 26) + 2 * ((x0 * x5) + (x1 * x4) + (x2 * x3)) + 38 * ((x6 * x9) + (x7 * x8));
            value.N5 = (t & ((1 << 25) - 1));

            t = (t >> 25) + 19 * (x8 * x8) + 2 * ((x0 * x6) + (x2 * x4) + (x3 * x3)) + 4 * (x1 * x5) + 76 * (x7 * x9);
            value.N6 = (t & ((1 << 26) - 1));

            t = (t >> 26) + 2 * ((x0 * x7) + (x1 * x6) + (x2 * x5) + (x3 * x4)) + 38 * (x8 * x9);
            value.N7 = (t & ((1 << 25) - 1));

            t = (t >> 25) + value.N8;
            value.N8 = (t & ((1 << 26) - 1));
            value.N9 += (t >> 26);
        }

        private static void Multiply(Long10 value, Long10 x, Long10 y)
        {
            long
                x0 = x.N0,
                x1 = x.N1,
                x2 = x.N2,
                x3 = x.N3,
                x4 = x.N4,
                x5 = x.N5,
                x6 = x.N6,
                x7 = x.N7,
                x8 = x.N8,
                x9 = x.N9;

            long
                y0 = y.N0,
                y1 = y.N1,
                y2 = y.N2,
                y3 = y.N3,
                y4 = y.N4,
                y5 = y.N5,
                y6 = y.N6,
                y7 = y.N7,
                y8 = y.N8,
                y9 = y.N9;

            long t = (x0 * y8) + (x2 * y6) + (x4 * y4) + (x6 * y2) + (x8 * y0) + 2 * ((x1 * y7) + (x3 * y5) + (x5 * y3) + (x7 * y1)) + 38 * (x9 * y9);
            value.N8 = (t & ((1 << 26) - 1));

            t = (t >> 26) + (x0 * y9) + (x1 * y8) + (x2 * y7) + (x3 * y6) + (x4 * y5) + (x5 * y4) + (x6 * y3) + (x7 * y2) + (x8 * y1) + (x9 * y0);
            value.N9 = (t & ((1 << 25) - 1));

            t = (x0 * y0) + 19 * ((t >> 25) + (x2 * y8) + (x4 * y6) + (x6 * y4) + (x8 * y2)) + 38 * ((x1 * y9) + (x3 * y7) + (x5 * y5) + (x7 * y3) + (x9 * y1));
            value.N0 = (t & ((1 << 26) - 1));

            t = (t >> 26) + (x0 * y1) + (x1 * y0) + 19 * ((x2 * y9) + (x3 * y8) + (x4 * y7) + (x5 * y6) + (x6 * y5) + (x7 * y4) + (x8 * y3) + (x9 * y2));
            value.N1 = (t & ((1 << 25) - 1));

            t = (t >> 25) + (x0 * y2) + (x2 * y0) + 19 * ((x4 * y8) + (x6 * y6) + (x8 * y4)) + 2 * (x1 * y1) + 38 * ((x3 * y9) + (x5 * y7) + (x7 * y5) + (x9 * y3));
            value.N2 = (t & ((1 << 26) - 1));

            t = (t >> 26) + (x0 * y3) + (x1 * y2) + (x2 * y1) + (x3 * y0) + 19 * ((x4 * y9) + (x5 * y8) + (x6 * y7) + (x7 * y6) + (x8 * y5) + (x9 * y4));
            value.N3 = (t & ((1 << 25) - 1));

            t = (t >> 25) + (x0 * y4) + (x2 * y2) + (x4 * y0) + 19 * ((x6 * y8) + (x8 * y6)) + 2 * ((x1 * y3) + (x3 * y1)) + 38 * ((x5 * y9) + (x7 * y7) + (x9 * y5));
            value.N4 = (t & ((1 << 26) - 1));

            t = (t >> 26) + (x0 * y5) + (x1 * y4) + (x2 * y3) + (x3 * y2) + (x4 * y1) + (x5 * y0) + 19 * ((x6 * y9) + (x7 * y8) + (x8 * y7) + (x9 * y6));
            value.N5 = (t & ((1 << 25) - 1));

            t = (t >> 25) + (x0 * y6) + (x2 * y4) + (x4 * y2) + (x6 * y0) + 19 * (x8 * y8) + 2 * ((x1 * y5) + (x3 * y3) + (x5 * y1)) + 38 * ((x7 * y9) + (x9 * y7));
            value.N6 = (t & ((1 << 26) - 1));

            t = (t >> 26) + (x0 * y7) + (x1 * y6) + (x2 * y5) + (x3 * y4) + (x4 * y3) + (x5 * y2) + (x6 * y1) + (x7 * y0) + 19 * ((x8 * y9) + (x9 * y8));
            value.N7 = (t & ((1 << 25) - 1));

            t = (t >> 25) + value.N8;
            value.N8 = (t & ((1 << 26) - 1));
            value.N9 += (t >> 26);
        }

        private static void Add(Long10 value, Long10 x, Long10 y)
        {
            value.N0 = x.N0 + y.N0;
            value.N1 = x.N1 + y.N1;
            value.N2 = x.N2 + y.N2;
            value.N3 = x.N3 + y.N3;
            value.N4 = x.N4 + y.N4;
            value.N5 = x.N5 + y.N5;
            value.N6 = x.N6 + y.N6;
            value.N7 = x.N7 + y.N7;
            value.N8 = x.N8 + y.N8;
            value.N9 = x.N9 + y.N9;
        }

        private static void Sub(Long10 value, Long10 x, Long10 y)
        {
            value.N0 = x.N0 - y.N0;
            value.N1 = x.N1 - y.N1;
            value.N2 = x.N2 - y.N2;
            value.N3 = x.N3 - y.N3;
            value.N4 = x.N4 - y.N4;
            value.N5 = x.N5 - y.N5;
            value.N6 = x.N6 - y.N6;
            value.N7 = x.N7 - y.N7;
            value.N8 = x.N8 - y.N8;
            value.N9 = x.N9 - y.N9;
        }

        private static void Copy(Long10 value, Long10 x)
        {
            value.N0 = x.N0;
            value.N1 = x.N1;
            value.N2 = x.N2;
            value.N3 = x.N3;
            value.N4 = x.N4;
            value.N5 = x.N5;
            value.N6 = x.N6;
            value.N7 = x.N7;
            value.N8 = x.N8;
            value.N9 = x.N9;
        }

        private static void Set(Long10 value, int x)
        {
            value.N0 = x;
            value.N1 = 0;
            value.N2 = 0;
            value.N3 = 0;
            value.N4 = 0;
            value.N5 = 0;
            value.N6 = 0;
            value.N7 = 0;
            value.N8 = 0;
            value.N9 = 0;
        }

        private static bool IsOverflow(Long10 value)
        {
            return (
                ((value.N0 > P26 - 19)) &
                ((value.N1 & value.N3 & value.N5 & value.N7 & value.N9) == P25) &
                ((value.N2 & value.N4 & value.N6 & value.N8) == P26)
                ) || (value.N9 > P25);
        }

        private static byte[] Pack(Long10 value)
        {
            var data = new byte[KeySize];
            int ld = (IsOverflow(value) ? 1 : 0) - ((value.N9 < 0) ? 1 : 0);
            int ud = ld * -(P25 + 1);
            ld *= 19;

            long t = ld + value.N0 + (value.N1 << 26);
            data[0] = (byte)t;
            data[1] = (byte)(t >> 8);
            data[2] = (byte)(t >> 16);
            data[3] = (byte)(t >> 24);

            t = (t >> 32) + (value.N2 << 19);
            data[4] = (byte)t;
            data[5] = (byte)(t >> 8);
            data[6] = (byte)(t >> 16);
            data[7] = (byte)(t >> 24);

            t = (t >> 32) + (value.N3 << 13);
            data[8] = (byte)t;
            data[9] = (byte)(t >> 8);
            data[10] = (byte)(t >> 16);
            data[11] = (byte)(t >> 24);

            t = (t >> 32) + (value.N4 << 6);
            data[12] = (byte)t;
            data[13] = (byte)(t >> 8);
            data[14] = (byte)(t >> 16);
            data[15] = (byte)(t >> 24);

            t = (t >> 32) + value.N5 + (value.N6 << 25);
            data[16] = (byte)t;
            data[17] = (byte)(t >> 8);
            data[18] = (byte)(t >> 16);
            data[19] = (byte)(t >> 24);

            t = (t >> 32) + (value.N7 << 19);
            data[20] = (byte)t;
            data[21] = (byte)(t >> 8);
            data[22] = (byte)(t >> 16);
            data[23] = (byte)(t >> 24);

            t = (t >> 32) + (value.N8 << 12);
            data[24] = (byte)t;
            data[25] = (byte)(t >> 8);
            data[26] = (byte)(t >> 16);
            data[27] = (byte)(t >> 24);

            t = (t >> 32) + ((value.N9 + ud) << 6);
            data[28] = (byte)t;
            data[29] = (byte)(t >> 8);
            data[30] = (byte)(t >> 16);
            data[31] = (byte)(t >> 24);

            return data;
        }

        private static void Clamp(byte[] value)
        {
            value[0] &= 0xF8;
            value[31] &= 0x7F;
            value[31] |= 0x40;
        }

        private static byte[] GetRandomBytes()
        {
            var data = new byte[KeySize];

            RandomNumberGenerator.Fill(data);

            return data;
        }
    }
}
