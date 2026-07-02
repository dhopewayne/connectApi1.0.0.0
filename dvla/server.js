const express = require('express');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const os = require('os');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] },
    pingTimeout: 60000,
    pingInterval: 25000
});

const PORT = process.env.PORT || 3000;

// ============= MIDDLEWARE =============
app.use(express.json({ limit: '50mb' }));
app.use(cors());

// ============= STORAGE =============
let latestData = {
    records: [],
    lastUpdate: null,
    source: null,
    table: null,
    count: 0
};

let connectedBranches = new Map();
let dataHistory = [];
const MAX_HISTORY = 50;

// ============= WHITELIST CONFIGURATION =============
// Support BOTH network ranges AND static IPs
// This is perfect for company networks with static configs

// 1. Network ranges (CIDR) - for dynamic IPs within a company network
let whitelistedNetworks = process.env.WHITELISTED_NETWORKS
    ? process.env.WHITELISTED_NETWORKS.split(',').map(network => network.trim()).filter(Boolean)
    : [];

// 2. Static IPs - for company servers with fixed IPs
let whitelistedStaticIps = process.env.WHITELISTED_STATIC_IPS
    ? process.env.WHITELISTED_STATIC_IPS.split(',').map(ip => ip.trim()).filter(Boolean)
    : [];

// 3. IP ranges (start-end) - for company subnets
let whitelistedIpRanges = [];

// Parse IP ranges from env if provided
if (process.env.WHITELISTED_IP_RANGES) {
    const ranges = process.env.WHITELISTED_IP_RANGES.split(',').map(range => range.trim()).filter(Boolean);
    for (const range of ranges) {
        const [start, end] = range.split('-');
        if (start && end) {
            whitelistedIpRanges.push({ start: start.trim(), end: end.trim() });
        }
    }
}

// 4. Company network with specific subnet mask (e.g., /16 for larger companies)
let whitelistedSubnets = process.env.WHITELISTED_SUBNETS
    ? process.env.WHITELISTED_SUBNETS.split(',').map(subnet => subnet.trim()).filter(Boolean)
    : [];

// ============= LOGGING =============
app.use((req, res, next) => {
    console.log(`\n🔵 [${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    next();
});

// ============= HELPER: Get Client IP =============
function getClientIp(req) {
    const candidates = [
        req.headers['cf-connecting-ip'],
        req.headers['x-forwarded-for'],
        req.headers['x-real-ip'],
        req.headers['true-client-ip'],
        req.headers['x-client-ip'],
        req.socket && req.socket.remoteAddress,
        req.connection && req.connection.remoteAddress
    ];

    for (let i = 0; i < candidates.length; i++) {
        const raw = candidates[i];
        if (!raw) continue;
        const ip = raw.split(',')[0].trim();
        if (!ip) continue;
        if (ip.startsWith('::ffff:')) return ip.slice(7);
        if (ip === '::1') return '127.0.0.1';
        return ip;
    }

    return 'Unknown';
}

// ============= HELPER: IP to Number =============
function ipToNumber(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return null;
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

// ============= HELPER: Check if IP is in network range (CIDR) =============
function isIpInCidrRange(ip, cidr) {
    if (!ip || !cidr) return false;
    
    const [network, maskBits] = cidr.split('/');
    if (!network || !maskBits) return false;
    
    const ipNum = ipToNumber(ip);
    const networkNum = ipToNumber(network);
    if (ipNum === null || networkNum === null) return false;
    
    const mask = parseInt(maskBits);
    const cidrMask = ~0 << (32 - mask);
    
    return (ipNum & cidrMask) === (networkNum & cidrMask);
}

// ============= HELPER: Check if IP is in IP range =============
function isIpInRange(ip, startIp, endIp) {
    if (!ip || !startIp || !endIp) return false;
    
    const ipNum = ipToNumber(ip);
    const startNum = ipToNumber(startIp);
    const endNum = ipToNumber(endIp);
    
    if (ipNum === null || startNum === null || endNum === null) return false;
    
    return ipNum >= startNum && ipNum <= endNum;
}

// ============= HELPER: Check if IP is in whitelisted subnet =============
function isIpInWhitelistedSubnet(ip, subnet) {
    if (!ip || !subnet) return false;
    
    // Support both CIDR and full subnet masks
    if (subnet.includes('/')) {
        return isIpInCidrRange(ip, subnet);
    }
    
    // Check if IP starts with subnet prefix
    const subnetParts = subnet.split('.');
    const ipParts = ip.split('.');
    
    if (subnetParts.length !== ipParts.length) return false;
    
    for (let i = 0; i < subnetParts.length; i++) {
        if (subnetParts[i] !== '*' && subnetParts[i] !== ipParts[i]) {
            return false;
        }
    }
    return true;
}

// ============= HELPER: Main IP Validation =============
function isIpWhitelisted(ip) {
    if (!ip) return false;
    
    // Check 1: Static IP whitelist
    if (whitelistedStaticIps.includes(ip)) {
        console.log(`   ✅ Static IP match: ${ip}`);
        return true;
    }
    
    // Check 2: Network ranges (CIDR)
    for (const network of whitelistedNetworks) {
        if (isIpInCidrRange(ip, network)) {
            console.log(`   ✅ Network range match: ${network}`);
            return true;
        }
    }
    
    // Check 3: IP ranges
    for (const range of whitelistedIpRanges) {
        if (isIpInRange(ip, range.start, range.end)) {
            console.log(`   ✅ IP range match: ${range.start} - ${range.end}`);
            return true;
        }
    }
    
    // Check 4: Subnet prefixes (for company networks with consistent prefixes)
    for (const subnet of whitelistedSubnets) {
        if (isIpInWhitelistedSubnet(ip, subnet)) {
            console.log(`   ✅ Subnet match: ${subnet}`);
            return true;
        }
    }
    
    return false;
}

// ============= HELPER: Get Network Info =============
function getNetworkInfo(ip) {
    const info = {
        ip: ip,
        is_static: whitelistedStaticIps.includes(ip),
        matching_network: null,
        matching_range: null,
        matching_subnet: null,
        is_whitelisted: false,
        network_type: 'unknown'
    };
    
    // Check CIDR networks
    for (const network of whitelistedNetworks) {
        if (isIpInCidrRange(ip, network)) {
            info.matching_network = network;
            info.is_whitelisted = true;
            break;
        }
    }
    
    // Check IP ranges
    if (!info.is_whitelisted) {
        for (const range of whitelistedIpRanges) {
            if (isIpInRange(ip, range.start, range.end)) {
                info.matching_range = range;
                info.is_whitelisted = true;
                break;
            }
        }
    }
    
    // Check subnets
    if (!info.is_whitelisted) {
        for (const subnet of whitelistedSubnets) {
            if (isIpInWhitelistedSubnet(ip, subnet)) {
                info.matching_subnet = subnet;
                info.is_whitelisted = true;
                break;
            }
        }
    }
    
    // Determine network type
    if (isIpInPrivateRange(ip)) {
        info.network_type = 'private';
    } else {
        info.network_type = 'public';
    }
    
    // If static IP is whitelisted, mark as whitelisted
    if (whitelistedStaticIps.includes(ip)) {
        info.is_whitelisted = true;
        info.is_static = true;
    }
    
    return info;
}

// ============= HELPER: Check if IP is in private range =============
function isIpInPrivateRange(ip) {
    if (!ip || ip === 'Unknown') return false;
    
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;
    if (parts.some(isNaN)) return false;
    
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
    
    // 127.0.0.0/8
    if (parts[0] === 127) return true;
    
    return false;
}

// ============= AUTHENTICATION =============
// Supports both static IPs and network ranges for company networks
const authenticateBranch = (req, res, next) => {
    const clientIp = getClientIp(req);
    const networkInfo = getNetworkInfo(clientIp);
    
    console.log(`\n🔐 AUTH CHECK (Company Network Ready):`);
    console.log(`   📍 Client IP:          ${clientIp}`);
    console.log(`   🔒 Is Private:         ${isIpInPrivateRange(clientIp)}`);
    console.log(`   📊 Network Type:       ${networkInfo.network_type}`);
    console.log(`   ✅ Is Whitelisted:     ${networkInfo.is_whitelisted}`);
    console.log(`   📋 Matching Config:    ${networkInfo.matching_network || networkInfo.matching_range || networkInfo.matching_subnet || 'None'}`);
    console.log(`   🔢 Static IP Match:    ${networkInfo.is_static}`);

    // Check if we have ANY whitelist configured
    const hasWhitelist = whitelistedStaticIps.length > 0 || 
                        whitelistedNetworks.length > 0 || 
                        whitelistedIpRanges.length > 0 || 
                        whitelistedSubnets.length > 0;

    if (!hasWhitelist) {
        console.log(`   ⚠️ No whitelist configured - allowing access (development mode)`);
        return next();
    }

    if (!networkInfo.is_whitelisted) {
        console.log(`   ❌ ACCESS DENIED - IP not in any whitelist`);
        
        // Determine what to suggest
        let suggestion = '';
        let exampleConfig = '';
        
        if (isIpInPrivateRange(clientIp)) {
            // For private IPs, suggest network ranges
            const ipParts = clientIp.split('.');
            suggestion = `Your IP is ${clientIp} in a private range.`;
            
            if (ipParts[0] === '192' && ipParts[1] === '168') {
                suggestion += ` Add your network: ${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0/24`;
                exampleConfig = `WHITELISTED_NETWORKS=${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0/24`;
            } else if (ipParts[0] === '10') {
                suggestion += ` Add your network: 10.0.0.0/8`;
                exampleConfig = `WHITELISTED_NETWORKS=10.0.0.0/8`;
            } else if (ipParts[0] === '172' && ipParts[1] >= 16 && ipParts[1] <= 31) {
                suggestion += ` Add your network: 172.16.0.0/12`;
                exampleConfig = `WHITELISTED_NETWORKS=172.16.0.0/12`;
            }
        } else {
            // For public IPs, suggest static IP whitelist
            suggestion = `Your IP (${clientIp}) is public. Add it as a static IP.`;
            exampleConfig = `WHITELISTED_STATIC_IPS=${clientIp}`;
        }
        
        return res.status(403).json({
            success: false,
            error: 'Access denied',
            reason: 'Your IP/network is not authorized to access this server.',
            your_ip: clientIp,
            network_info: {
                is_private: isIpInPrivateRange(clientIp),
                network_type: networkInfo.network_type
            },
            current_whitelist: {
                static_ips: whitelistedStaticIps,
                networks: whitelistedNetworks,
                ip_ranges: whitelistedIpRanges,
                subnets: whitelistedSubnets
            },
            suggestion: suggestion,
            how_to_fix: {
                method_1: `Add to .env: ${exampleConfig}`,
                method_2: `POST to /whitelist with your network/ip`,
                method_3: `For static IPs: WHITELISTED_STATIC_IPS=${clientIp}`,
                method_4: `For company network: WHITELISTED_NETWORKS=192.168.0.0/16`
            },
            company_network_help: {
                static_ip: 'If IP is static, add to WHITELISTED_STATIC_IPS',
                network_range: 'If IP is dynamic within company, add to WHITELISTED_NETWORKS',
                subnet: 'If company uses specific subnet, add to WHITELISTED_SUBNETS'
            }
        });
    }

    console.log(`   ✅ ACCESS GRANTED — ${networkInfo.is_static ? 'Static IP' : 'Network range'} match`);
    next();
};

// Apply authentication to protected routes
app.use('/testresults', authenticateBranch);
app.use('/data',        authenticateBranch);

// ============= ENDPOINT: Whitelist Management =============
// Supports adding static IPs, network ranges, and IP ranges

// GET - View all whitelists
app.get('/whitelist', (req, res) => {
    res.json({
        success: true,
        whitelist: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks,
            ip_ranges: whitelistedIpRanges,
            subnets: whitelistedSubnets
        },
        counts: {
            static_ips: whitelistedStaticIps.length,
            networks: whitelistedNetworks.length,
            ip_ranges: whitelistedIpRanges.length,
            subnets: whitelistedSubnets.length,
            total: whitelistedStaticIps.length + 
                   whitelistedNetworks.length + 
                   whitelistedIpRanges.length + 
                   whitelistedSubnets.length
        },
        usage: {
            add_static_ip: 'POST /whitelist/static with { "ips": ["192.168.1.100"] }',
            add_network: 'POST /whitelist/network with { "networks": ["192.168.1.0/24"] }',
            add_range: 'POST /whitelist/range with { "ranges": ["192.168.1.1-192.168.1.254"] }',
            add_subnet: 'POST /whitelist/subnet with { "subnets": ["192.168.1"] }'
        }
    });
});

// POST - Add static IPs
app.post('/whitelist/static', (req, res) => {
    const { ips } = req.body;
    const clientIp = getClientIp(req);

    console.log(`\n📋 ADD STATIC IPs from ${clientIp}`);
    console.log(`   IPs to add: ${ips}`);

    if (!ips) {
        return res.status(400).json({
            success: false,
            error: 'Missing field: ips',
            example: { ips: ['192.168.1.100', '10.0.0.5'] }
        });
    }

    const incoming = (Array.isArray(ips) ? ips : [ips])
        .map(ip => ip.trim())
        .filter(Boolean);

    // Validate IPs
    const invalidIps = [];
    const validIps = [];
    for (const ip of incoming) {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipv4Regex.test(ip) && ip.split('.').every(num => parseInt(num) >= 0 && parseInt(num) <= 255)) {
            validIps.push(ip);
        } else {
            invalidIps.push(ip);
        }
    }

    const added = [];
    const alreadyExist = [];
    for (const ip of validIps) {
        if (!whitelistedStaticIps.includes(ip)) {
            whitelistedStaticIps.push(ip);
            added.push(ip);
        } else {
            alreadyExist.push(ip);
        }
    }

    res.json({
        success: true,
        message: `Added ${added.length} static IP(s)`,
        added: added,
        already_existed: alreadyExist,
        invalid: invalidIps,
        static_ips: whitelistedStaticIps,
        note: 'Static IPs are ideal for company servers with fixed IP addresses'
    });
});

// POST - Add network ranges (CIDR)
app.post('/whitelist/network', (req, res) => {
    const { networks } = req.body;
    const clientIp = getClientIp(req);

    console.log(`\n📋 ADD NETWORK RANGES from ${clientIp}`);
    console.log(`   Networks to add: ${networks}`);

    if (!networks) {
        return res.status(400).json({
            success: false,
            error: 'Missing field: networks',
            example: { networks: ['192.168.1.0/24', '10.0.0.0/8'] }
        });
    }

    const incoming = (Array.isArray(networks) ? networks : [networks])
        .map(network => network.trim())
        .filter(Boolean);

    const invalidNetworks = [];
    const validNetworks = [];
    for (const network of incoming) {
        const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
        if (cidrRegex.test(network)) {
            const parts = network.split('/');
            const ipParts = parts[0].split('.');
            const mask = parseInt(parts[1]);
            if (ipParts.every(num => parseInt(num) >= 0 && parseInt(num) <= 255) && mask >= 0 && mask <= 32) {
                validNetworks.push(network);
            } else {
                invalidNetworks.push(network);
            }
        } else {
            invalidNetworks.push(network);
        }
    }

    const added = [];
    const alreadyExist = [];
    for (const network of validNetworks) {
        if (!whitelistedNetworks.includes(network)) {
            whitelistedNetworks.push(network);
            added.push(network);
        } else {
            alreadyExist.push(network);
        }
    }

    res.json({
        success: true,
        message: `Added ${added.length} network range(s)`,
        added: added,
        already_existed: alreadyExist,
        invalid: invalidNetworks,
        networks: whitelistedNetworks,
        note: 'Network ranges are ideal for company networks with dynamic IPs'
    });
});

// POST - Add IP ranges
app.post('/whitelist/range', (req, res) => {
    const { ranges } = req.body;
    const clientIp = getClientIp(req);

    console.log(`\n📋 ADD IP RANGES from ${clientIp}`);
    console.log(`   Ranges to add: ${ranges}`);

    if (!ranges) {
        return res.status(400).json({
            success: false,
            error: 'Missing field: ranges',
            example: { ranges: ['192.168.1.1-192.168.1.254'] }
        });
    }

    const incoming = (Array.isArray(ranges) ? ranges : [ranges])
        .map(range => range.trim())
        .filter(Boolean);

    const validRanges = [];
    const invalidRanges = [];
    
    for (const range of incoming) {
        const [start, end] = range.split('-');
        if (start && end) {
            const startTrim = start.trim();
            const endTrim = end.trim();
            
            // Validate IPs
            const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (ipv4Regex.test(startTrim) && ipv4Regex.test(endTrim)) {
                const startNum = ipToNumber(startTrim);
                const endNum = ipToNumber(endTrim);
                if (startNum !== null && endNum !== null && startNum <= endNum) {
                    validRanges.push({ start: startTrim, end: endTrim });
                } else {
                    invalidRanges.push(range);
                }
            } else {
                invalidRanges.push(range);
            }
        } else {
            invalidRanges.push(range);
        }
    }

    const added = [];
    const alreadyExist = [];
    for (const range of validRanges) {
        const exists = whitelistedIpRanges.some(r => r.start === range.start && r.end === range.end);
        if (!exists) {
            whitelistedIpRanges.push(range);
            added.push(`${range.start}-${range.end}`);
        } else {
            alreadyExist.push(`${range.start}-${range.end}`);
        }
    }

    res.json({
        success: true,
        message: `Added ${added.length} IP range(s)`,
        added: added,
        already_existed: alreadyExist,
        invalid: invalidRanges,
        ranges: whitelistedIpRanges,
        note: 'IP ranges are ideal for company subnets with specific IP allocations'
    });
});

// POST - Add subnets
app.post('/whitelist/subnet', (req, res) => {
    const { subnets } = req.body;
    const clientIp = getClientIp(req);

    console.log(`\n📋 ADD SUBNETS from ${clientIp}`);
    console.log(`   Subnets to add: ${subnets}`);

    if (!subnets) {
        return res.status(400).json({
            success: false,
            error: 'Missing field: subnets',
            example: { subnets: ['192.168.1', '10.0'] }
        });
    }

    const incoming = (Array.isArray(subnets) ? subnets : [subnets])
        .map(subnet => subnet.trim())
        .filter(Boolean);

    const added = [];
    const alreadyExist = [];
    for (const subnet of incoming) {
        if (!whitelistedSubnets.includes(subnet)) {
            whitelistedSubnets.push(subnet);
            added.push(subnet);
        } else {
            alreadyExist.push(subnet);
        }
    }

    res.json({
        success: true,
        message: `Added ${added.length} subnet(s)`,
        added: added,
        already_existed: alreadyExist,
        subnets: whitelistedSubnets,
        note: 'Subnets are ideal for large company networks with consistent IP prefixes'
    });
});

// DELETE - Remove from whitelist
app.delete('/whitelist', (req, res) => {
    const { type, value } = req.body;
    const clientIp = getClientIp(req);

    console.log(`\n🗑️ REMOVE FROM WHITELIST from ${clientIp}`);
    console.log(`   Type: ${type}, Value: ${value}`);

    if (!type || !value) {
        return res.status(400).json({
            success: false,
            error: 'Missing fields: type and value',
            example: { type: 'static', value: '192.168.1.100' },
            types: ['static', 'network', 'range', 'subnet']
        });
    }

    let removed = false;
    let message = '';

    switch (type) {
        case 'static':
            const staticIndex = whitelistedStaticIps.indexOf(value);
            if (staticIndex !== -1) {
                whitelistedStaticIps.splice(staticIndex, 1);
                removed = true;
                message = `Removed static IP ${value}`;
            }
            break;
            
        case 'network':
            const networkIndex = whitelistedNetworks.indexOf(value);
            if (networkIndex !== -1) {
                whitelistedNetworks.splice(networkIndex, 1);
                removed = true;
                message = `Removed network ${value}`;
            }
            break;
            
        case 'range':
            const [start, end] = value.split('-');
            const rangeIndex = whitelistedIpRanges.findIndex(r => r.start === start && r.end === end);
            if (rangeIndex !== -1) {
                whitelistedIpRanges.splice(rangeIndex, 1);
                removed = true;
                message = `Removed IP range ${value}`;
            }
            break;
            
        case 'subnet':
            const subnetIndex = whitelistedSubnets.indexOf(value);
            if (subnetIndex !== -1) {
                whitelistedSubnets.splice(subnetIndex, 1);
                removed = true;
                message = `Removed subnet ${value}`;
            }
            break;
            
        default:
            return res.status(400).json({
                success: false,
                error: 'Invalid type',
                types: ['static', 'network', 'range', 'subnet']
            });
    }

    if (!removed) {
        return res.status(404).json({
            success: false,
            error: `${type} ${value} not found in whitelist`
        });
    }

    res.json({
        success: true,
        message: message,
        remaining: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks,
            ip_ranges: whitelistedIpRanges,
            subnets: whitelistedSubnets
        }
    });
});

// ============= ENDPOINT: Check Your Network Status =============
app.get('/my-network-status', (req, res) => {
    const clientIp = getClientIp(req);
    const networkInfo = getNetworkInfo(clientIp);
    
    console.log(`\n🌐 NETWORK STATUS CHECK from ${clientIp}`);
    
    // Determine recommended configuration for company networks
    let recommendations = [];
    if (isIpInPrivateRange(clientIp)) {
        recommendations.push({
            type: 'Network Range (CIDR)',
            value: getRecommendedCidr(clientIp),
            description: 'Best for company networks with dynamic IPs'
        });
        recommendations.push({
            type: 'Static IP',
            value: clientIp,
            description: 'Best for company servers with fixed IPs'
        });
        recommendations.push({
            type: 'IP Range',
            value: getRecommendedIpRange(clientIp),
            description: 'Best for company subnets with specific IP allocations'
        });
    }
    
    res.json({
        success: true,
        your_ip: clientIp,
        network_info: {
            is_private: isIpInPrivateRange(clientIp),
            is_whitelisted: networkInfo.is_whitelisted,
            matching_config: networkInfo.matching_network || 
                           networkInfo.matching_range || 
                           networkInfo.matching_subnet || 
                           'None',
            is_static_ip: networkInfo.is_static
        },
        current_whitelist: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks,
            ip_ranges: whitelistedIpRanges,
            subnets: whitelistedSubnets
        },
        recommendations: recommendations,
        company_network_config: {
            static_ip: `WHITELISTED_STATIC_IPS=${clientIp}`,
            network_range: `WHITELISTED_NETWORKS=${getRecommendedCidr(clientIp)}`,
            ip_range: `WHITELISTED_IP_RANGES=${getRecommendedIpRange(clientIp)}`,
            subnet: `WHITELISTED_SUBNETS=${getRecommendedSubnet(clientIp)}`
        },
        timestamp: new Date().toISOString()
    });
});

// ============= HELPER: Get Recommended CIDR =============
function getRecommendedCidr(ip) {
    const parts = ip.split('.');
    if (parts[0] === '192' && parts[1] === '168') {
        return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    } else if (parts[0] === '10') {
        return '10.0.0.0/8';
    } else if (parts[0] === '172' && parts[1] >= 16 && parts[1] <= 31) {
        return '172.16.0.0/12';
    }
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

// ============= HELPER: Get Recommended IP Range =============
function getRecommendedIpRange(ip) {
    const parts = ip.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.1-${parts[0]}.${parts[1]}.${parts[2]}.254`;
}

// ============= HELPER: Get Recommended Subnet =============
function getRecommendedSubnet(ip) {
    const parts = ip.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}`;
}

// ============= OTHER ENDPOINTS =============
app.get('/', (req, res) => {
    res.json({
        name: 'Company Network Authentication Server',
        status: 'online',
        version: '2.0.0',
        authentication: {
            type: 'Multi-Method Whitelist',
            methods: [
                'Static IP Whitelist (Company servers with fixed IPs)',
                'Network Range Whitelist (Dynamic IPs within company)',
                'IP Range Whitelist (Specific company subnets)',
                'Subnet Whitelist (Company network prefixes)'
            ]
        },
        endpoints: {
            'GET /whitelist': 'View all whitelists',
            'POST /whitelist/static': 'Add static IPs',
            'POST /whitelist/network': 'Add network ranges (CIDR)',
            'POST /whitelist/range': 'Add IP ranges',
            'POST /whitelist/subnet': 'Add subnets',
            'DELETE /whitelist': 'Remove from whitelist',
            'GET /my-network-status': 'Check your network status'
        },
        timestamp: new Date().toISOString()
    });
});

// ============= START SERVER =============
server.listen(PORT, () => {
    console.log(`
    ═══════════════════════════════════════════════════════
    🏢 COMPANY NETWORK AUTHENTICATION SERVER
    ═══════════════════════════════════════════════════════
    📍 URL:        http://localhost:${PORT}
    
    🔐 Whitelist Configuration:
       Static IPs:  ${whitelistedStaticIps.length > 0 ? whitelistedStaticIps.join(', ') : 'None'}
       Networks:    ${whitelistedNetworks.length > 0 ? whitelistedNetworks.join(', ') : 'None'}
       IP Ranges:   ${whitelistedIpRanges.length > 0 ? whitelistedIpRanges.map(r => `${r.start}-${r.end}`).join(', ') : 'None'}
       Subnets:     ${whitelistedSubnets.length > 0 ? whitelistedSubnets.join(', ') : 'None'}
    
    📡 Company Network Setup:
       1. Check your IP:         GET /my-network-status
       2. Add static IP:         POST /whitelist/static
       3. Add network range:     POST /whitelist/network
       4. Add IP range:          POST /whitelist/range
       5. Add subnet:            POST /whitelist/subnet
    
    💡 Example for Company Network:
       curl -X POST /whitelist/static \\
         -H "Content-Type: application/json" \\
         -d '{"ips": ["192.168.1.100", "192.168.1.101"]}'
       
       curl -X POST /whitelist/network \\
         -H "Content-Type: application/json" \\
         -d '{"networks": ["192.168.1.0/24"]}'
    ═══════════════════════════════════════════════════════
    `);
});