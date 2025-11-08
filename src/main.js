function cidrCalculator() {
    return {
        rangeToCidr: {
            startIp: '',
            endIp: '',
            result: '',
            error: false
        },
        cidrToRange: {
            cidr: '',
            result: '',
            error: false
        },

        // Helper: Detect if IPv4 or IPv6
        getIpVersion(ip) {
            if (ip.includes(':')) return 6;
            if (ip.includes('.')) return 4;
            return 0;
        },

        // IPv4 to binary
        ipv4ToBinary(ip) {
            const parts = ip.split('.').map(Number);
            if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
                return null;
            }
            return parts.reduce((acc, part) => (acc << 8) + part, 0) >>> 0;
        },

        // Binary to IPv4
        binaryToIpv4(binary) {
            return [
                (binary >>> 24) & 0xFF,
                (binary >>> 16) & 0xFF,
                (binary >>> 8) & 0xFF,
                binary & 0xFF
            ].join('.');
        },

        // IPv6 to binary array (8 groups of 16 bits)
        ipv6ToBinaryArray(ip) {
            try {
                let parts = ip.toLowerCase().split(':');
                let doubleColonIndex = parts.indexOf('');

                if (doubleColonIndex !== -1) {
                    const before = parts.slice(0, doubleColonIndex).filter(p => p);
                    const after = parts.slice(doubleColonIndex + 1).filter(p => p);
                    const missing = 8 - before.length - after.length;
                    parts = [...before, ...Array(missing).fill('0'), ...after];
                }

                const groups = parts.map(p => parseInt(p || '0', 16));
                if (groups.length !== 8 || groups.some(g => isNaN(g) || g < 0 || g > 0xFFFF)) {
                    return null;
                }
                return groups;
            } catch {
                return null;
            }
        },

        // Binary array to IPv6
        binaryArrayToIpv6(groups) {
            const normalize = g => g.toString(16).replace(/^0+/, '') || '0';
            let bestStart = -1;
            let bestLen = 0;
            let currStart = -1;

            for (let i = 0; i < 8; i++) {
                if (groups[i] === 0) {
                    if (currStart === -1) currStart = i;
                } else if (currStart !== -1) {
                    const len = i - currStart;
                    if (len > bestLen) {
                        bestStart = currStart;
                        bestLen = len;
                    }
                    currStart = -1;
                }
            }

            if (currStart !== -1) {
                const len = 8 - currStart;
                if (len > bestLen) {
                    bestStart = currStart;
                    bestLen = len;
                }
            }

            if (bestLen > 1) {
                const before = groups.slice(0, bestStart).map(normalize);
                const after = groups.slice(bestStart + bestLen).map(normalize);
                let result = '';
                if (before.length) {
                    result += before.join(':');
                }
                result += '::';
                if (after.length) {
                    result += after.join(':');
                }
                return result === '::' ? result : result.replace(/(^|:)0+(?=[0-9a-f])/g, '$1');
            }

            return groups.map(normalize).join(':');
        },

        ipv6GroupsToBigInt(groups) {
            return groups.reduce((acc, group) => (acc << 16n) | BigInt(group), 0n);
        },

        bigIntToIpv6(value) {
            let temp = value;
            const groups = [];
            for (let i = 0; i < 8; i++) {
                groups.unshift(Number(temp & 0xFFFFn));
                temp >>= 16n;
            }
            return this.binaryArrayToIpv6(groups);
        },

        getLargestBlockSize(current, remaining, maxBits) {
            let blockSize = current & -current;
            if (blockSize === 0n) {
                blockSize = 1n << BigInt(maxBits);
            }
            while (blockSize > remaining) {
                blockSize >>= 1n;
            }
            return blockSize;
        },

        blockSizeToPrefix(blockSize, maxBits) {
            let prefix = maxBits;
            let size = blockSize;
            while (size > 1n) {
                size >>= 1n;
                prefix--;
            }
            return prefix;
        },

        ipv4RangeToCidrs(start, end) {
            const result = [];
            let current = BigInt(start);
            const targetEnd = BigInt(end);

            while (current <= targetEnd) {
                const remaining = targetEnd - current + 1n;
                const blockSize = this.getLargestBlockSize(current, remaining, 32);
                const prefix = this.blockSizeToPrefix(blockSize, 32);
                result.push(`${this.binaryToIpv4(Number(current))}/${prefix}`);
                current += blockSize;
            }

            return result;
        },

        ipv6RangeToCidrs(start, end) {
            const result = [];
            let current = start;

            while (current <= end) {
                const remaining = end - current + 1n;
                const blockSize = this.getLargestBlockSize(current, remaining, 128);
                const prefix = this.blockSizeToPrefix(blockSize, 128);
                result.push(`${this.bigIntToIpv6(current)}/${prefix}`);
                current += blockSize;
            }

            return result;
        },

        // Calculate CIDR prefix from netmask
        calculatePrefix(start, end, isIpv6) {
            if (isIpv6) {
                const maxBits = 128;
                for (let prefix = maxBits; prefix >= 0; prefix--) {
                    const mask = this.createIpv6Mask(prefix);
                    const networkStart = start.map((val, idx) => val & mask[idx]);
                    const networkEnd = end.map((val, idx) => val & mask[idx]);

                    // Check if start and end are in the same network
                    if (this.compareIpv6Arrays(networkStart, networkEnd) !== 0) {
                        continue;
                    }

                    const broadcastEnd = networkStart.map((val, idx) => val | (~mask[idx] & 0xFFFF));

                    if (this.compareIpv6Arrays(start, networkStart) === 0 &&
                        this.compareIpv6Arrays(end, broadcastEnd) === 0) {
                        return prefix;
                    }
                }
                return -1;
            } else {
                const maxBits = 32;
                for (let prefix = maxBits; prefix >= 0; prefix--) {
                    const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
                    const networkStart = (start & mask) >>> 0;
                    const networkEnd = (end & mask) >>> 0;

                    // Check if start and end are in the same network
                    if (networkStart !== networkEnd) {
                        continue;
                    }

                    const hostMask = (~mask) >>> 0;
                    const broadcast = (networkStart | hostMask) >>> 0;

                    if (start === networkStart && end === broadcast) {
                        return prefix;
                    }
                }
                return -1;
            }
        },

        // Create IPv6 mask
        createIpv6Mask(prefix) {
            const mask = Array(8).fill(0);
            for (let i = 0; i < 8; i++) {
                const bitsInGroup = Math.min(16, Math.max(0, prefix - i * 16));
                mask[i] = (0xFFFF << (16 - bitsInGroup)) & 0xFFFF;
            }
            return mask;
        },

        // Compare IPv6 arrays
        compareIpv6Arrays(a, b) {
            for (let i = 0; i < 8; i++) {
                if (a[i] < b[i]) return -1;
                if (a[i] > b[i]) return 1;
            }
            return 0;
        },

        // Convert Range to CIDR
        convertRangeToCidr() {
            this.rangeToCidr.result = '';
            this.rangeToCidr.error = false;

            const startIp = this.rangeToCidr.startIp.trim();
            const endIp = this.rangeToCidr.endIp.trim();

            if (!startIp || !endIp) {
                this.rangeToCidr.error = true;
                this.rangeToCidr.result = 'Please enter both start and end IP addresses.';
                return;
            }

            const startVersion = this.getIpVersion(startIp);
            const endVersion = this.getIpVersion(endIp);

            if (startVersion !== endVersion || startVersion === 0) {
                this.rangeToCidr.error = true;
                this.rangeToCidr.result = 'Both IPs must be valid and of the same version (IPv4 or IPv6).';
                return;
            }

            if (startVersion === 4) {
                const start = this.ipv4ToBinary(startIp);
                const end = this.ipv4ToBinary(endIp);

                if (start === null || end === null) {
                    this.rangeToCidr.error = true;
                    this.rangeToCidr.result = 'Invalid IPv4 address format.';
                    return;
                }

                if (start > end) {
                    this.rangeToCidr.error = true;
                    this.rangeToCidr.result = 'Start IP must be less than or equal to End IP.';
                    return;
                }

                const cidrs = this.ipv4RangeToCidrs(start, end);
                this.rangeToCidr.result = `<ul class="mb-0">${cidrs.map(cidr => `<li><strong>${cidr}</strong></li>`).join('')}</ul>`;
            } else {
                const startGroups = this.ipv6ToBinaryArray(startIp);
                const endGroups = this.ipv6ToBinaryArray(endIp);

                if (!startGroups || !endGroups) {
                    this.rangeToCidr.error = true;
                    this.rangeToCidr.result = 'Invalid IPv6 address format.';
                    return;
                }

                if (this.compareIpv6Arrays(startGroups, endGroups) > 0) {
                    this.rangeToCidr.error = true;
                    this.rangeToCidr.result = 'Start IP must be less than or equal to End IP.';
                    return;
                }

                const startBigInt = this.ipv6GroupsToBigInt(startGroups);
                const endBigInt = this.ipv6GroupsToBigInt(endGroups);
                const cidrs = this.ipv6RangeToCidrs(startBigInt, endBigInt);
                this.rangeToCidr.result = `<ul class="mb-0">${cidrs.map(cidr => `<li><strong>${cidr}</strong></li>`).join('')}</ul>`;
            }
        },

        // Convert CIDR to Range
        convertCidrToRange() {
            this.cidrToRange.result = '';
            this.cidrToRange.error = false;

            const cidr = this.cidrToRange.cidr.trim();
            const parts = cidr.split('/');

            if (parts.length !== 2) {
                this.cidrToRange.error = true;
                this.cidrToRange.result = 'Invalid CIDR format. Use format: IP/prefix (e.g., 192.168.1.0/24)';
                return;
            }

            const ip = parts[0];
            const prefix = parseInt(parts[1]);
            const version = this.getIpVersion(ip);

            if (version === 0) {
                this.cidrToRange.error = true;
                this.cidrToRange.result = 'Invalid IP address format.';
                return;
            }

            if (version === 4) {
                if (isNaN(prefix) || prefix < 0 || prefix > 32) {
                    this.cidrToRange.error = true;
                    this.cidrToRange.result = 'IPv4 prefix must be between 0 and 32.';
                    return;
                }

                const binary = this.ipv4ToBinary(ip);
                if (binary === null) {
                    this.cidrToRange.error = true;
                    this.cidrToRange.result = 'Invalid IPv4 address.';
                    return;
                }

                const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
                const network = binary & mask;
                const broadcast = network | (~mask >>> 0);
                const totalHosts = Math.pow(2, 32 - prefix);
                const usableHosts = prefix < 31 ? totalHosts - 2 : totalHosts;

                this.cidrToRange.result = `
                                <div><strong>Network:</strong> ${this.binaryToIpv4(network)}</div>
                                <div><strong>First Host:</strong> ${prefix < 31 ? this.binaryToIpv4(network + 1) : this.binaryToIpv4(network)}</div>
                                <div><strong>Last Host:</strong> ${prefix < 31 ? this.binaryToIpv4(broadcast - 1) : this.binaryToIpv4(broadcast)}</div>
                                <div><strong>Broadcast:</strong> ${this.binaryToIpv4(broadcast)}</div>
                                <div><strong>Netmask:</strong> ${this.binaryToIpv4(mask)}</div>
                                <div><strong>Total Addresses:</strong> ${totalHosts.toLocaleString()}</div>
                                <div><strong>Usable Hosts:</strong> ${usableHosts.toLocaleString()}</div>
                            `;
            } else {
                if (isNaN(prefix) || prefix < 0 || prefix > 128) {
                    this.cidrToRange.error = true;
                    this.cidrToRange.result = 'IPv6 prefix must be between 0 and 128.';
                    return;
                }

                const groups = this.ipv6ToBinaryArray(ip);
                if (!groups) {
                    this.cidrToRange.error = true;
                    this.cidrToRange.result = 'Invalid IPv6 address.';
                    return;
                }

                const mask = this.createIpv6Mask(prefix);
                const network = groups.map((val, idx) => val & mask[idx]);
                const broadcast = network.map((val, idx) => val | (~mask[idx] & 0xFFFF));

                const totalAddresses = prefix <= 64 ? `2^${128 - prefix}` : `${Math.pow(2, 128 - prefix).toLocaleString()}`;

                this.cidrToRange.result = `
                                <div><strong>Network:</strong> ${this.binaryArrayToIpv6(network)}</div>
                                <div><strong>First Address:</strong> ${this.binaryArrayToIpv6(network)}</div>
                                <div><strong>Last Address:</strong> ${this.binaryArrayToIpv6(broadcast)}</div>
                                <div><strong>Prefix Length:</strong> /${prefix}</div>
                                <div><strong>Total Addresses:</strong> ${totalAddresses}</div>
                            `;
            }
        }
    };
}