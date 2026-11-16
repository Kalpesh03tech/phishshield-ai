#!/usr/bin/env node
/**
 * SSL/TLS Certificate Inspector for Deployment Pipelines & CI/CD
 * 
 * Features:
 * - Zero external dependencies (uses native Node.js `tls`, `net`, `url` modules)
 * - SNI (Server Name Indication) and custom port support (domain.com:8443)
 * - Wildcard & Subject Alternative Names (SAN) support
 * - Emits details ONLY if SSL is present and active (suppresses non-SSL/HTTP)
 * - Supports CLI arguments, subdomains, JSON output, and CI exit codes
 */

const tls = require('tls');
const net = require('net');
const url = require('url');

const DEFAULT_TIMEOUT_MS = 5000;

/**
 * Parses a target string (URL, hostname, or hostname:port)
 * @param {string} target 
 * @returns {{ host: string, port: number, servername: string }}
 */
function parseTarget(target) {
    let clean = target.trim();
    if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
        clean = 'https://' + clean;
    }

    try {
        const parsed = new URL(clean);
        const host = parsed.hostname;
        const port = parsed.port ? parseInt(parsed.port, 10) : 443;
        return { host, port, servername: host };
    } catch (err) {
        // Fallback for raw host:port strings
        const parts = target.split(':');
        return {
            host: parts[0],
            port: parts[1] ? parseInt(parts[1], 10) : 443,
            servername: parts[0]
        };
    }
}

/**
 * Probes target host:port for SSL certificate details.
 * Returns null if the host does not have an SSL certificate or is unencrypted.
 * 
 * @param {string} target - Domain, URL, or host:port
 * @param {number} timeoutMs - Socket timeout in milliseconds
 * @returns {Promise<object|null>} Certificate metadata or null if no SSL
 */
function inspectSSL(target, timeoutMs = DEFAULT_TIMEOUT_MS) {
    return new Promise((resolve) => {
        const { host, port, servername } = parseTarget(target);

        // First check if TCP port is open
        const socket = net.createConnection({ host, port, timeout: timeoutMs });

        socket.on('timeout', () => {
            socket.destroy();
            resolve(null);
        });

        socket.on('error', () => {
            socket.destroy();
            resolve(null); // No SSL or connection refused -> return null
        });

        socket.on('connect', () => {
            // Upgrade connection to TLS with SNI
            const tlsOptions = {
                socket: socket,
                servername: servername,
                rejectUnauthorized: false // Allow inspecting expired/self-signed certs
            };

            const tlsSocket = tls.connect(tlsOptions, () => {
                const cert = tlsSocket.getPeerCertificate(true);

                if (!cert || !Object.keys(cert).length) {
                    tlsSocket.destroy();
                    return resolve(null);
                }

                // Extract Certificate Authority (Issuer)
                const issuer = cert.issuer ? (
                    cert.issuer.O || cert.issuer.CN || cert.issuer.OU || 'Unknown CA'
                ) : 'Unknown CA';

                // Extract Validity Dates
                const validFrom = new Date(cert.valid_from);
                const validTo = new Date(cert.valid_to);
                const now = new Date();

                const msLeft = validTo.getTime() - now.getTime();
                const daysRemaining = Math.floor(msLeft / (1000 * 60 * 60 * 24));
                const isExpired = daysRemaining < 0;

                // Status determination
                let status = 'VALID';
                if (isExpired) {
                    status = 'EXPIRED';
                } else if (daysRemaining <= 14) {
                    status = 'EXPIRING_SOON';
                }

                // Extract Wildcard & SAN names
                const subjectAltNames = cert.subjectaltname 
                    ? cert.subjectaltname.split(', ').map(s => s.replace(/^DNS:/, ''))
                    : [];
                
                const isWildcard = (cert.subject && cert.subject.CN && cert.subject.CN.startsWith('*.')) ||
                                   subjectAltNames.some(san => san.startsWith('*.'));

                const result = {
                    target: `${host}:${port}`,
                    domain: host,
                    port: port,
                    has_ssl: true,
                    issuer: issuer,
                    subject: cert.subject ? (cert.subject.CN || host) : host,
                    valid_from: validFrom.toISOString().split('T')[0],
                    valid_to: validTo.toISOString().split('T')[0],
                    expiry_date: validTo.toUTCString(),
                    days_remaining: daysRemaining,
                    status: status,
                    is_wildcard: isWildcard,
                    sans: subjectAltNames
                };

                tlsSocket.destroy();
                resolve(result);
            });

            tlsSocket.on('timeout', () => {
                tlsSocket.destroy();
                resolve(null);
            });

            tlsSocket.on('error', () => {
                tlsSocket.destroy();
                resolve(null);
            });
        });
    });
}

/**
 * Inspect multiple domains in parallel
 * @param {string[]} targets 
 * @param {number} timeoutMs 
 * @returns {Promise<object[]>} Array of SSL info (non-SSL targets omitted)
 */
async function inspectMultiple(targets, timeoutMs = DEFAULT_TIMEOUT_MS) {
    const promises = targets.map(t => inspectSSL(t, timeoutMs));
    const results = await Promise.all(promises);
    // Filter out nulls (where SSL is not present)
    return results.filter(r => r !== null && r.has_ssl);
}

// ======================== CLI RUNNER ========================
async function main() {
    const args = process.argv.slice(2);

    if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
        console.log(`
Usage:
  node scripts/ssl-checker.js [options] <domain1> <domain2:port> <url3>...

Options:
  --json          Output results in JSON format
  --timeout <ms>  Socket timeout in milliseconds (default: 5000)
  -h, --help      Show this help message

Examples:
  node scripts/ssl-checker.js google.com github.com
  node scripts/ssl-checker.js sub1.example.com sub2.example.com:8443 --json
`);
        process.exit(0);
    }

    const isJson = args.includes('--json');
    const timeoutIdx = args.indexOf('--timeout');
    const timeout = timeoutIdx !== -1 && args[timeoutIdx + 1] ? parseInt(args[timeoutIdx + 1], 10) : DEFAULT_TIMEOUT_MS;

    const targets = args.filter(a => !a.startsWith('--') && (timeoutIdx === -1 || a !== args[timeoutIdx + 1]));

    if (targets.length === 0) {
        process.exit(0);
    }

    const sslResults = await inspectMultiple(targets, timeout);

    // If no SSL present across targets, output nothing as requested
    if (sslResults.length === 0) {
        process.exit(0);
    }

    if (isJson) {
        console.log(JSON.stringify(sslResults, null, 2));
    } else {
        console.log('\n🔒 SSL Certificate Report:');
        console.log('='.repeat(70));
        
        sslResults.forEach(r => {
            const statusSymbol = r.status === 'VALID' ? '✅' : (r.status === 'EXPIRING_SOON' ? '⚠️' : '❌');
            console.log(`Domain:          ${r.domain}${r.port !== 443 ? ':' + r.port : ''}`);
            console.log(`Status:          ${statusSymbol} ${r.status} (${r.days_remaining} days left)`);
            console.log(`CA Issuer:       ${r.issuer}`);
            console.log(`Expiry Date:     ${r.valid_to} (${r.expiry_date})`);
            if (r.is_wildcard) console.log(`Wildcard Cert:   Yes (* SAN match)`);
            console.log('-'.repeat(70));
        });
    }

    // Exit code 1 if any cert is expired (useful for CI/CD fail-fast)
    const hasExpired = sslResults.some(r => r.status === 'EXPIRED');
    process.exit(hasExpired ? 1 : 0);
}

if (require.main === module) {
    main();
}

module.exports = { inspectSSL, inspectMultiple };
