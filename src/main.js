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
            let hex = groups.map(g => g.toString(16)).join(':');
            // Compress zeros
            hex = hex.replace(/\b0+/g, '0');
            hex = hex.replace(/(:0)+:/, '::');
            return hex;
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

                const prefix = this.calculatePrefix(start, end, false);
                if (prefix === -1) {
                    this.rangeToCidr.error = true;
                    this.rangeToCidr.result = 'The IP range cannot be represented as a single CIDR block.';
                    return;
                }

                this.rangeToCidr.result = `<strong>${startIp}/${prefix}</strong>`;
            } else {
                const start = this.ipv6ToBinaryArray(startIp);
                const end = this.ipv6ToBinaryArray(endIp);

                if (!start || !end) {
                    this.rangeToCidr.error = true;
                    this.rangeToCidr.result = 'Invalid IPv6 address format.';
                    return;
                }

                if (this.compareIpv6Arrays(start, end) > 0) {
                    this.rangeToCidr.error = true;
                    this.rangeToCidr.result = 'Start IP must be less than or equal to End IP.';
                    return;
                }

                const prefix = this.calculatePrefix(start, end, true);
                if (prefix === -1) {
                    this.rangeToCidr.error = true;
                    this.rangeToCidr.result = 'The IP range cannot be represented as a single CIDR block.';
                    return;
                }

                this.rangeToCidr.result = `<strong>${startIp}/${prefix}</strong>`;
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