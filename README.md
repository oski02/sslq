# sslq - Post-Quantum Cryptography Scanner for SSL/TLS

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![GitHub](https://img.shields.io/github/stars/oski02/sslq?style=social)](https://github.com/oski02/sslq)

**sslq** is a powerful **Post-Quantum Cryptography (PQC) scanner** and detector for SSL/TLS connections. Analyze websites and servers to detect quantum-resistant cryptography algorithms including **Kyber (ML-KEM)**, **Dilithium (ML-DSA)**, and other NIST-standardized post-quantum algorithms.

🔐 **Detect quantum-safe encryption** | 🚀 **Fast SSL/TLS analysis** | 📊 **JSON export** | 🎨 **Beautiful output**

---

## 🌟 Why Use sslq?

As quantum computers advance, traditional cryptography (RSA, ECDSA) will become vulnerable. **Post-Quantum Cryptography (PQC)** is the next generation of encryption designed to resist quantum attacks.

**sslq** helps you:
- ✅ **Audit SSL/TLS security** against quantum threats
- ✅ **Detect Kyber/ML-KEM** implementation in websites
- ✅ **Verify PQC compliance** for security standards
- ✅ **Research quantum-resistant cryptography** adoption
- ✅ **Test your own** PQC implementations

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/oski02/sslq.git
cd sslq

# Install dependencies
pip install -r requirements.txt

# Run your first scan
python3 sslq.py -u https://cloudflare.com
```

### Basic Usage

```bash
# Scan a single website for Post-Quantum Cryptography
python3 sslq.py -u https://google.com

# Scan multiple URLs from a file
python3 sslq.py -f urls.txt

# Export results to JSON
python3 sslq.py -u https://cloudflare.com -j results.json

# Verbose mode with detailed output
python3 sslq.py -u https://microsoft.com -v
```

---

## 🔍 What is Post-Quantum Cryptography?

**Post-Quantum Cryptography (PQC)** refers to cryptographic algorithms that are secure against attacks by quantum computers. In 2024, NIST standardized three key PQC algorithms:

1. **ML-KEM (Kyber)** - Key Encapsulation Mechanism
2. **ML-DSA (Dilithium)** - Digital Signatures
3. **SLH-DSA (SPHINCS+)** - Stateless Hash-based Signatures

Major tech companies like **Google**, **Cloudflare**, **Microsoft**, and **Meta** have already implemented **Kyber/ML-KEM** in their TLS connections.

---

## ✨ Features

### Post-Quantum Cryptography Detection
- 🔐 **NIST Standardized Algorithms**: Kyber (ML-KEM), Dilithium (ML-DSA), SPHINCS+ (SLH-DSA)
- 🔄 **Hybrid Algorithms**: X25519+Kyber, P-256+Kyber, X25519MLKEM768
- 🎯 **Additional PQC Candidates**: FALCON, NTRU, SABER, BIKE, HQC, FrodoKEM

### SSL/TLS Analysis
- 📡 **TLS 1.2 & 1.3 Support**
- 🔑 **Key Exchange Group Detection** (using OpenSSL)
- 🎫 **X.509 Certificate Analysis**
- 🔐 **Cipher Suite Inspection**
- 📊 **Signature Algorithm Detection**

### Output & Export
- 🎨 **Color-coded terminal output** (similar to sslyze)
- 📄 **JSON export** for integration
- 📋 **Bulk scanning** from URL lists
- ⚡ **Fast concurrent analysis**

---

## 📖 Detailed Usage Examples

### Scan for Kyber/ML-KEM Support

```bash
# Check if a website uses Kyber (ML-KEM) for quantum resistance
python3 sslq.py -u https://google.com
```

**Output:**
```
================================================================================
Target: google.com:443
================================================================================

[✓] POST-QUANTUM CRYPTOGRAPHY DETECTED
    PQC in key exchange: X25519MLKEM768

Key Exchange:
  Negotiated Group: X25519MLKEM768
  Group Type: POST-QUANTUM HYBRID
    - KYBER: mlkem
    - HYBRID: x25519mlkem
```

### Bulk PQC Scanner

```bash
# Create a list of websites to scan
cat > websites.txt << EOF
https://cloudflare.com
https://google.com
https://microsoft.com
https://facebook.com
https://github.com
EOF

# Scan all websites for post-quantum cryptography
python3 sslq.py -f websites.txt

# Export results
python3 sslq.py -f websites.txt -j pqc_scan_results.json
```

### Advanced Options

```bash
# Custom timeout for slow connections
python3 sslq.py -u example.com:8443 -t 20

# Disable colored output (for logs)
python3 sslq.py -u example.com --no-color > scan.log

# Verbose mode with detailed progress
python3 sslq.py -f urls.txt -v -j results.json
```

---

## 🎯 Detected Algorithms

### NIST Post-Quantum Cryptography Standards (2024)

| Algorithm | Type | Status | Detection |
|-----------|------|--------|-----------|
| **ML-KEM (Kyber)** | Key Exchange | ✅ Standardized | ✅ Supported |
| **ML-DSA (Dilithium)** | Digital Signature | ✅ Standardized | ✅ Supported |
| **SLH-DSA (SPHINCS+)** | Signature | ✅ Standardized | ✅ Supported |

### Hybrid PQC Implementations

- **X25519MLKEM768** - X25519 + ML-KEM-768 (Used by Google, Cloudflare, Meta)
- **X25519Kyber768** - X25519 + Kyber-768
- **P256Kyber768** - P-256 + Kyber-768
- **secp256r1Kyber768** - secp256r1 + Kyber-768

### Additional PQC Candidates

FALCON, NTRU, SABER, BIKE, HQC, FrodoKEM and more.

---

## 🌐 Real-World PQC Adoption

**Websites currently using Post-Quantum Cryptography (December 2024):**

| Company | Algorithm | Status |
|---------|-----------|--------|
| 🔵 **Google** | X25519MLKEM768 | ✅ Active |
| 🟠 **Cloudflare** | X25519MLKEM768 | ✅ Active |
| 🟢 **Microsoft** | X25519MLKEM768 | ✅ Active |
| 🔵 **Meta/Facebook** | X25519MLKEM768 | ✅ Active |

*Test these yourself with sslq!*

---

## 📊 Command Line Options

```
usage: sslq.py [-h] (-u URL | -f FILE) [-t TIMEOUT] [-v] [-j JSON] [--no-color]

Post-Quantum Cryptography Scanner for SSL/TLS

Options:
  -h, --help            Show help message and exit
  -u, --url URL         Single URL to analyze for PQC
  -f, --file FILE       File containing URLs (one per line)
  -t, --timeout TIMEOUT Connection timeout in seconds (default: 10)
  -v, --verbose         Verbose output with detailed progress
  -j, --json JSON       Export scan results to JSON file
  --no-color            Disable colored terminal output

Examples:
  sslq.py -u https://cloudflare.com
  sslq.py -u example.com:443
  sslq.py -f websites.txt
  sslq.py -f urls.txt -j results.json
  sslq.py -u google.com --timeout 15 --verbose
```

---

## 🔧 Requirements

- **Python 3.7+**
- **cryptography** >= 41.0.0 (for certificate parsing)
- **OpenSSL 3.0+** (for enhanced PQC group detection)

```bash
pip install -r requirements.txt
```

---

## 🛠️ How It Works

**sslq** uses a dual-detection approach for comprehensive PQC analysis:

### 1. Python SSL Library
- Analyzes cipher suites
- Parses X.509 certificates
- Detects signature algorithms

### 2. OpenSSL CLI Integration
- Detects TLS 1.3 key exchange groups
- Identifies ML-KEM/Kyber implementations
- Extracts negotiated algorithms

### Detection Layers:
1. **Cipher Suite Analysis** - Symmetric encryption algorithms
2. **Key Exchange Groups** - Where PQC is currently implemented (Kyber/ML-KEM)
3. **Certificate Signatures** - Future PQC signature algorithms

---

## 🎓 Learning Resources

### What is Quantum Threat?
Quantum computers will break current encryption (RSA, ECC) using Shor's algorithm. Organizations must migrate to quantum-resistant cryptography now.

### Why Kyber (ML-KEM)?
Kyber was selected by NIST as the primary algorithm for post-quantum key exchange due to its:
- Small key sizes
- Fast performance
- Strong security guarantees

### Useful Links
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-KEM Standard (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
- [Cloudflare PQC Blog](https://blog.cloudflare.com/post-quantum-tunnel/)
- [Google Security Blog - Kyber](https://security.googleblog.com/2024/09/a-new-path-for-kyber-on-web.html)

---

## 📈 Use Cases

### 1. Security Auditing
Verify if your infrastructure supports quantum-resistant encryption.

```bash
python3 sslq.py -u https://your-api.company.com
```

### 2. Compliance Verification
Check PQC compliance for security certifications and standards.

```bash
python3 sslq.py -f production-servers.txt -j compliance-report.json
```

### 3. Research & Analysis
Study post-quantum cryptography adoption across the internet.

```bash
python3 sslq.py -f top-1000-websites.txt -j pqc-research.json
```

### 4. Testing PQC Implementations
Validate your own post-quantum TLS implementations.

```bash
python3 sslq.py -u https://test.pqc.myserver.com:8443 -v
```

---

## 🤝 Contributing

Contributions are welcome! This is an open-source project for the security community.

- 🐛 **Bug reports**: Open an issue
- 💡 **Feature requests**: Open an issue with [FEATURE] tag
- 🔧 **Pull requests**: Fork, improve, and submit PR
- ⭐ **Star the repo**: Help others discover sslq

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details.

Free to use for personal, educational, and commercial purposes.

---

## 🙏 Acknowledgments

- **NIST** for standardizing Post-Quantum Cryptography
- **Cloudflare, Google, Microsoft** for early PQC adoption
- **OpenSSL** team for PQC support
- Security research community

---

## 🔍 Keywords

post quantum cryptography, pqc scanner, kyber detector, ml-kem scanner, tls scanner, ssl scanner, quantum resistant, quantum safe cryptography, nist pqc, dilithium, sphincs, hybrid encryption, x25519mlkem768, post-quantum tls, quantum cryptography detector, ssl security scanner, tls security audit, kyber implementation, ml-kem detector, quantum resistant ssl, pqc compliance, quantum safe tls

---

## 📞 Support

- 🐛 **Issues**: https://github.com/oski02/sslq/issues
- ⭐ **Star this repo** if you find it useful!
- 🔄 **Share** with the security community

---

**Ready for the post-quantum era?** 🔐🚀

Test your SSL/TLS security today:
```bash
git clone https://github.com/oski02/sslq.git && cd sslq && python3 sslq.py -u https://yoursite.com
```
