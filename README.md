# sslq - SSL/TLS Post-Quantum Cryptography Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

**sslq** es una herramienta en Python para detectar soporte de **Criptografía Post-Cuántica (PQC)** en conexiones TLS/SSL de sitios web.

## Características

- ✅ Analiza conexiones TLS/SSL en busca de algoritmos post-cuánticos
- ✅ Detecta algoritmos PQC incluyendo:
  - **NIST Selected Algorithms**: Kyber (ML-KEM), Dilithium (ML-DSA), SPHINCS+ (SLH-DSA)
  - **Otros candidatos**: FALCON, NTRU, SABER, BIKE, HQC, FrodoKEM
  - **Algoritmos híbridos**: X25519+Kyber, P-256+Kyber, etc.
- ✅ Analiza cipher suites y certificados X.509
- ✅ Detecta grupos de intercambio de claves usando OpenSSL
- ✅ Salida formateada al estilo sslyze con colores
- ✅ Soporte para análisis individual o masivo (archivo con URLs)
- ✅ Exportación de resultados a JSON

## Instalación

```bash
# Clonar o descargar el repositorio
cd sslq

# Instalar dependencias
pip install -r requirements.txt

# Dar permisos de ejecución (opcional)
chmod +x sslq.py
```

## Uso Rápido

```bash
# Analizar una URL
python3 sslq.py -u https://cloudflare.com

# Analizar múltiples URLs desde archivo
python3 sslq.py -f urls.txt

# Guardar resultados en JSON
python3 sslq.py -f urls.txt -j results.json

# Modo verbose
python3 sslq.py -u example.com -v
```

## Ejemplos

### URL individual

```bash
# Forma básica
python3 sslq.py -u https://example.com

# Con timeout personalizado (20 segundos)
python3 sslq.py -u example.com -t 20

# Especificar puerto
python3 sslq.py -u example.com:8443

# Sin colores (para redirección)
python3 sslq.py -u example.com --no-color > output.txt
```

### Múltiples URLs desde archivo

```bash
# Crear archivo con URLs (una por línea)
cat > urls.txt << EOF
https://cloudflare.com
https://google.com
https://github.com
example.com:443
EOF

# Analizar todas las URLs
python3 sslq.py -f urls.txt

# Con timeout y verbose
python3 sslq.py -f urls.txt -t 20 -v

# Guardar en JSON
python3 sslq.py -f urls.txt -j pqc_report.json
```

## Formato del archivo de URLs

El archivo debe contener una URL por línea. Se permiten comentarios con `#`:

```text
# Sitios para analizar
https://cloudflare.com
https://google.com
example.com:443
github.com

# Sitios con posible soporte PQC
https://test.example.com:8443
```

## Salida de Ejemplo

```
================================================================================
Target: cloudflare.com:443
================================================================================

[✓] POST-QUANTUM CRYPTOGRAPHY DETECTED
    PQC in key exchange: X25519MLKEM768

SSL/TLS Information:
  Protocol Version: TLSv1.3

Cipher Suite:
  Name: TLS_AES_256_GCM_SHA384
  Protocol: TLSv1.3
  Strength: 256 bits
  PQC Status: Classical only

Key Exchange:
  Negotiated Group: X25519MLKEM768
  Group Type: POST-QUANTUM HYBRID
    - KYBER: mlkem
    - HYBRID: x25519mlkem

Certificate Information:
  Subject CN: cloudflare.com
  Issuer CN: WE1
  Valid From: 2025-11-14T20:28:36+00:00
  Valid Until: 2026-02-12T21:28:32+00:00
  Signature Algorithm: ecdsa-with-SHA256
  Public Key: ECPublicKey (256 bits)

--------------------------------------------------------------------------------
```

## Algoritmos PQC Detectados

### Algoritmos NIST Seleccionados (2024)
- **Kyber / ML-KEM**: Key Encapsulation Mechanism (principal para intercambio de claves)
- **Dilithium / ML-DSA**: Digital Signature Algorithm
- **SPHINCS+ / SLH-DSA**: Stateless Hash-based signatures

### Otros Candidatos
- **FALCON**: Fast Fourier Lattice-based Compact Signatures
- **NTRU**: Lattice-based encryption
- **SABER**: Module-LWR based KEM
- **BIKE**: Bit Flipping Key Encapsulation
- **HQC**: Hamming Quasi-Cyclic
- **FrodoKEM**: Learning With Errors based KEM

### Algoritmos Híbridos (Implementados actualmente)
- **X25519MLKEM768**: X25519 + ML-KEM-768 (usado por Google, Cloudflare, Meta)
- **P256Kyber768**: P-256 + Kyber-768
- Otras combinaciones PQC + Clásico

## Opciones de Línea de Comandos

```
usage: sslq.py [-h] (-u URL | -f FILE) [-t TIMEOUT] [-v] [-j JSON] [--no-color]

SSL/TLS Post-Quantum Cryptography Scanner

Opciones:
  -h, --help            Mostrar ayuda y salir
  -u URL, --url URL     URL individual a analizar
  -f FILE, --file FILE  Archivo con URLs (una por línea)
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout de conexión en segundos (default: 10)
  -v, --verbose         Salida detallada (muestra progreso)
  -j JSON, --json JSON  Guardar resultados en archivo JSON
  --no-color            Deshabilitar salida con colores

Ejemplos:
  sslq.py -u https://example.com
  sslq.py -u example.com:443
  sslq.py -f urls.txt
  sslq.py -u example.com --json output.json
  sslq.py -f urls.txt --timeout 15 --verbose
```

## Requisitos

- Python 3.7+
- cryptography >= 41.0.0
- OpenSSL 3.0+ (para detección avanzada de grupos PQC)

## Cómo Funciona

**sslq** utiliza dos métodos complementarios para detectar PQC:

1. **Librería Python SSL**: Analiza cipher suites y certificados X.509
2. **OpenSSL CLI** (si está disponible): Detecta grupos de intercambio de claves TLS 1.3 como X25519MLKEM768

La detección de PQC se realiza en tres niveles:
- **Cipher Suite**: Algoritmos de cifrado simétrico
- **Key Exchange Group**: Algoritmos de intercambio de claves (donde está el PQC actualmente)
- **Certificate Signature**: Algoritmo de firma del certificado

## Sitios con PQC Habilitado (Diciembre 2024)

Sitios que actualmente soportan X25519MLKEM768:
- ✅ Google (google.com)
- ✅ Cloudflare (cloudflare.com)
- ✅ Microsoft (microsoft.com)
- ✅ Meta/Facebook (facebook.com)
- ✅ Y muchos otros...

## Limitaciones

- La detección se basa en nombres de algoritmos en cipher suites, grupos y certificados
- Algunos servidores pueden no exponer información PQC en handshake TLS estándar
- Algoritmos PQC experimentales o propietarios pueden no ser detectados
- TLS 1.3 con encriptación de handshake puede limitar la información visible sin OpenSSL

## Casos de Uso

- **Auditoría de seguridad**: Verificar si tus servicios usan PQC
- **Investigación**: Estudiar adopción de PQC en internet
- **Compliance**: Verificar cumplimiento con estándares post-cuánticos
- **Testing**: Validar implementaciones PQC en entornos de prueba
- **Educación**: Aprender sobre criptografía post-cuántica

## Referencias

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
- [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final)
- [Cloudflare PQC Research](https://blog.cloudflare.com/post-quantum-tunnel/)
- [Google PQC](https://security.googleblog.com/2024/09/a-new-path-for-kyber-on-web.html)

## Contribuciones

Mejoras y sugerencias son bienvenidas. Este script es para propósitos educativos y de investigación.

## Licencia

MIT License

## Autor

Desarrollado para la comunidad de seguridad y criptografía.

---

**¿Preparado para la era post-cuántica?** 🔐🚀
