# Firma Digital UDS · Actividad A5

**Materia:** Seguridad Informática I · **Universidad:** Universidad Domingo Savio
**Docente:** Ing. José Abraham Mita Huanca
**Integrantes:** Daniel Maldonado Céspedes · Leonardo Nogales Torres

Aplicación web, desarrollada por el grupo, para **generar llaves, firmar digitalmente un PDF y validar la firma**.

| Página | Qué hace |
|---|---|
| **1. Generar llaves** (`/generar`) | Crea un par de llaves **RSA** y un **certificado X.509** autofirmado con OpenSSL (a través de la biblioteca `cryptography`). Entrega la llave pública, el certificado, la llave privada cifrada y una identidad `.p12`. Muestra los comandos de `openssl` equivalentes. |
| **2. Firmar PDF** (`/firmar`) | Sube un PDF y tu identidad `.p12`: calcula el hash **SHA-256** del documento, lo firma con la llave privada (RSA) e incrusta la firma en el PDF (estándar `adbe.pkcs7.detached`). Si el PDF ya tenía firmas, las conserva y **añade** la nueva. |
| **3. Validar firma** (`/validar`) | Sube el PDF firmado y, opcionalmente, el certificado o la llave pública del firmante. Informa, por cada firma, si el documento está **íntegro**, si la firma es **válida** y si la identidad es **confiable**. |

## Tecnología

Python 3 · **Flask** (páginas web) · **cryptography** (llaves, certificados, PKCS#12; usa OpenSSL por dentro) · **pyHanko** (firma y validación de firmas en PDF).
Toda la criptografía está en `firma_digital.py`; `app.py` solo maneja la parte web.

## Requisitos

- **Python 3.10 o superior** (probado con 3.12).
- Conexión a internet **solo para instalar** las dependencias; la aplicación funciona sin internet.

## Instalación

Ejecuta los comandos **dentro de la carpeta `firma-digital-web`**.

### Windows (PowerShell o CMD)

```powershell
py --version                      # debe ser 3.10 o superior
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Si PowerShell bloquea la activación: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, o usa CMD.

### Kali Linux

```bash
python3 --version                 # debe ser 3.10 o superior
sudo apt update && sudo apt install -y python3-venv     # solo si falta
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Ejecución

```bash
python app.py
```

Abre en el navegador: **http://127.0.0.1:5000**. Para detener la aplicación: `Ctrl + C`.
La aplicación escucha **solo en tu computadora** (127.0.0.1); no es accesible desde otras máquinas.

## Flujo de trabajo (cada integrante)

1. **Generar llaves:** completa el formulario (nombre, organización, país, contraseña) y descarga los archivos.
   - **Públicos (se entregan):** `publica_<nombre>.pem` y `certificado_<nombre>.pem`.
   - **Privados (NO se entregan):** `privada_cifrada_<nombre>.pem` e `identidad_<nombre>.p12`.
2. **Firmar PDF:** sube el PDF y tu `.p12`, escribe la contraseña y descarga el PDF firmado.
   Para la **segunda firma**, sube el PDF ya firmado por el primer integrante (sin modificarlo) con la identidad del segundo.
3. **Validar firma:** sube el PDF firmado y los `certificado_*.pem` (o las `publica_*.pem`) de los firmantes.

### Resultados posibles de la validación

| Resultado | Significado |
|---|---|
| **Firma válida** (verde) | El documento no fue modificado y la identidad del firmante está confirmada. |
| **Íntegra, identidad no confirmada** (ámbar) | El documento no fue modificado, pero no se proporcionó el certificado o la llave pública del firmante. Es lo esperado con certificados autofirmados. |
| **Firma no válida** (rojo) | El documento fue modificado después de firmarse (o la firma está dañada). |

## Verificación independiente (línea de comandos)

```bash
# Datos y huella del certificado
openssl x509 -in certificado_<nombre>.pem -noout -text
openssl x509 -in certificado_<nombre>.pem -noout -fingerprint -sha256

# El certificado autofirmado es coherente consigo mismo
openssl verify -CAfile certificado_<nombre>.pem certificado_<nombre>.pem

# La llave pública del certificado coincide con la entregada
openssl x509 -in certificado_<nombre>.pem -pubkey -noout

# Firmas de un PDF (Kali: sudo apt install poppler-utils)
pdfsig documento_firmado.pdf
```

También se puede abrir el PDF en **Adobe Acrobat Reader** y revisar el panel de firmas.

## Pruebas automáticas

```bash
python -m unittest discover -s tests -v
```

39 pruebas: generación de llaves, firma, doble firma, detección de manipulación, interoperabilidad con OpenSSL y `pdfsig`, y el flujo web completo.

## Seguridad

- Usa llaves creadas **solo para esta actividad**. La llave privada y el `.p12` **nunca** se entregan ni se suben a un repositorio (el `.gitignore` los excluye).
- La aplicación **no guarda** llaves ni contraseñas en disco ni en registros. Los PDF firmados permanecen en memoria 15 minutos solo para poder descargarlos.
- **No modifiques** un PDF después de firmarlo (abrirlo y guardarlo, imprimirlo a PDF o editarlo invalida la firma).
- Es una herramienta **didáctica**. En producción se usan certificados emitidos por una **entidad certificadora** de confianza, sello de tiempo y revocación.

## Solución de problemas

| Problema | Solución |
|---|---|
| `No module named 'flask'` / `pyhanko` | Activa el entorno virtual y ejecuta `pip install -r requirements.txt`. |
| `pip` falla al instalar `lxml` o `pyHanko` | Comprueba que tu Python sea **3.10 o superior** (`py --version`). |
| `error: externally-managed-environment` (Kali) | Usa el entorno virtual (ver instalación). |
| «La contraseña es incorrecta» al firmar | La contraseña es la que escribiste al generar las llaves; no se puede recuperar. |
| «El certificado todavía no es válido» | Revisa la fecha y la hora de tu computadora. |
| «Address already in use» | El puerto 5000 está ocupado: cierra la otra instancia de la aplicación. |
