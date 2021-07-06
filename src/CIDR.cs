using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Threading.Tasks;

namespace CIDRCalc
{
    public struct CIDR
    {
        private readonly IPAddress _address;
        private readonly uint _networkLength;
        private readonly uint _bits;

        public CIDR(IPAddress address, uint networkLength)
        {
            _address = address;
            _networkLength = networkLength;
            _bits = AddressFamilyBits(address.AddressFamily);
            if (networkLength > _bits)
            {
                throw new ArgumentException("Invalid network length " + networkLength + " for " + address.AddressFamily);
            }
        }

        public IPAddress NetworkAddress => _address;

        public IPAddress LastAddress => IPAddressAdd(_address, (new BigInteger(1) << (int)HostLength) - 1);

        public uint NetworkLength => _networkLength;

        public uint AddressBits => _bits;

        public uint HostLength => _bits - _networkLength;

        public override string ToString()
        {
            return _address + "/" + NetworkLength;
        }

        public string ToShortString()
        {
            if (_networkLength == _bits) return _address.ToString();
            return _address + "/" + NetworkLength;
        }

        /* static helpers */
        public static IPAddress IPAddressAdd(IPAddress address, BigInteger i)
        {
            return IPFromUnsigned(IPToUnsigned(address) + i, address.AddressFamily);
        }

        public static uint AddressFamilyBits(AddressFamily family)
        {
            switch (family)
            {
                case AddressFamily.InterNetwork:
                    return 32;
                case AddressFamily.InterNetworkV6:
                    return 128;
                default:
                    throw new ArgumentException("Invalid address family " + family);
            }
        }

        private static BigInteger IPToUnsigned(IPAddress addr)
        {
            /* Need to reverse addr bytes for BigInteger; prefix with 0 byte to force unsigned BigInteger
			 * read BigInteger bytes as: bytes[n] bytes[n-1] ... bytes[0], address is bytes[0] bytes[1] .. bytes[n] */
            var b = addr.GetAddressBytes();
            var unsigned = new byte[b.Length + 1];
            for (var i = 0; i < b.Length; ++i)
            {
                unsigned[i] = b[(b.Length - 1) - i];
            }
            unsigned[b.Length] = 0;
            return new(unsigned);
        }

        private static byte[] GetUnsignedBytes(BigInteger unsigned, uint bytes)
        {
            /* reverse bytes again. check that now higher bytes are actually used */
            if (unsigned.Sign < 0) throw new ArgumentException("argument must be >= 0");
            var data = unsigned.ToByteArray();
            var result = new byte[bytes];
            for (var i = 0; i < bytes && i < data.Length; ++i)
            {
                result[bytes - 1 - i] = data[i];
            }
            for (var i = bytes; i < data.Length; ++i)
            {
                if (data[i] != 0) throw new ArgumentException("argument doesn't fit in requested number of bytes");
            }
            return result;
        }

        private static IPAddress IPFromUnsigned(BigInteger unsigned, AddressFamily family)
        {
            /* IPAddress(byte[]) constructor picks family from array size */
            switch (family)
            {
                case AddressFamily.InterNetwork:
                    return new(GetUnsignedBytes(unsigned, 4));
                case AddressFamily.InterNetworkV6:
                    return new(GetUnsignedBytes(unsigned, 16));
                default:
                    throw new ArgumentException("AddressFamily " + family.ToString() + " not supported");
            }
        }

        /* splits set [first..last] of unsigned integers into disjoint slices { x,..., x + 2^k - 1 | x mod 2^k == 0 }
		 *  covering exaclty the given set.
		 * yields the slices ordered by x as tuples (x, k)
		 * This code relies on the fact that BigInteger can't overflow; temporary results may need more bits than last is using.
		 */
        public static IEnumerable<Tuple<BigInteger, uint>> Split(BigInteger first, BigInteger last)
        {
            if (first > last) yield break;
            if (first < 0) throw new ArgumentException();
            last += 1;
            /* mask == 1 << len */
            BigInteger mask = 1;
            uint len = 0;
            while (first + mask <= last)
            {
                if ((first & mask) != 0)
                {
                    yield return new(first, len);
                    first += mask;
                }
                mask <<= 1;
                ++len;
            }
            while (first < last)
            {
                mask >>= 1;
                --len;
                if ((last & mask) != 0)
                {
                    yield return new(first, len);
                    first += mask;
                }
            }
        }

        public static IEnumerable<CIDR> Split(IPAddress first, IPAddress last)
        {
            if (first.AddressFamily != last.AddressFamily)
            {
                throw new ArgumentException("AddressFamilies don't match");
            }
            var family = first.AddressFamily;
            var bits = AddressFamilyBits(family); /* split on numbers returns host length, CIDR takes network length */
            foreach (var (item1, item2) in Split(IPToUnsigned(first), IPToUnsigned(last)))
            {
                yield return new(IPFromUnsigned(item1, family), bits - item2);
            }
        }
    }
}
