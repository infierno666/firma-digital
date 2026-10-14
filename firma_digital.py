# -*- coding: utf-8 -*-
"""
firma_digital.py  -  Núcleo criptográfico de la aplicación de firma digital (Actividad A5)
Seguridad Informática I · Universidad Domingo Savio

Este módulo NO depende de Flask: contiene toda la criptografía, de modo que se puede probar
y explicar por separado de la parte web.

Tres operaciones:
  1) generar_identidad()  Genera un par de llaves RSA y un certificado X.509 autofirmado
                          (con la biblioteca `cryptography`, que usa OpenSSL por dentro) y los
                          empaqueta en PEM y en un archivo PKCS#12 (.p12) protegido con contraseña.
  2) firmar_pdf()         Incrusta una firma digital en el PDF (estándar PDF: adbe.pkcs7.detached,
                          SHA-256 + RSA) usando la librería pyHanko. Si el PDF ya tenía firmas, las
                          conserva y AÑADE la nueva (actualización incremental).
  3) validar_pdf()        Comprueba cada firma del PDF: integridad (¿cambió el documento?),
                          validez criptográfica y confianza del certificado.

Conceptos clave (se explican en el informe):
  * Firmar = calcular el hash SHA-256 del documento y cifrarlo con la llave PRIVADA (RSA).
  * Verificar = descifrar la firma con la llave PÚBLICA y comparar con el hash del documento.
  * El certificado X.509 liga la llave pública con una identidad. Si es autofirmado, nadie
    garantiza esa identidad: por eso el verificador debe CONFIAR explícitamente en él.
"""

import datetime
import hashlib
import io
import logging
import re
import unicodedata
from dataclasses import dataclass, field

from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import ModificationLevel
from pyhanko.stamp import TextStampStyle
from pyhanko_certvalidator import ValidationContext

# Las bibliotecas escriben mensajes técnicos de "error" cuando un certificado no es confiable;
# eso es un resultado normal de la validación y se muestra de forma clara en la interfaz.
for _nombre in ("pyhanko", "pyhanko_certvalidator"):
    logging.getLogger(_nombre).setLevel(logging.CRITICAL)

BOLIVIA = datetime.timezone(datetime.timedelta(hours=-4), "BOT")   # hora de Bolivia (UTC-4)
TAMANOS_RSA = (2048, 3072)


class ErrorFirma(Exception):
    """Error con un mensaje pensado para mostrarse al usuario."""


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
def _formato_huella(datos: bytes) -> str:
    """Huella SHA-256 en el formato de OpenSSL: AA:BB:CC:..."""
    h = hashlib.sha256(datos).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def nombre_seguro(texto: str) -> str:
    """Convierte un nombre en un texto apto para nombres de archivo: 'José Pérez' -> 'jose_perez'."""
    sin_tildes = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()
    limpio = re.sub(r"[^A-Za-z0-9]+", "_", sin_tildes).strip("_").lower()
    return limpio or "firmante"


def _solo_latin1(texto: str) -> str:
    """La firma visible usa una fuente básica (Latin-1); se evitan caracteres que no soporta."""
    return texto.encode("latin-1", "replace").decode("latin-1")


def _validar_texto(valor: str, etiqueta: str, minimo: int = 0, maximo: int = 64) -> str:
    valor = (valor or "").strip()
    if len(valor) < minimo:
        raise ErrorFirma(f"{etiqueta} es obligatorio (mínimo {minimo} caracteres).")
    if len(valor) > maximo:
        raise ErrorFirma(f"{etiqueta} no puede superar {maximo} caracteres.")
    if any(unicodedata.category(c).startswith("C") for c in valor):
        raise ErrorFirma(f"{etiqueta} contiene caracteres no permitidos.")
    return valor


# ---------------------------------------------------------------------------
# 1) GENERACIÓN DE LLAVES Y CERTIFICADO
# ---------------------------------------------------------------------------
@dataclass
class Identidad:
    nombre: str
    sujeto: str
    bits: int
    serie_hex: str
    valido_desde: datetime.datetime
    valido_hasta: datetime.datetime
    huella_certificado: str      # SHA-256 del certificado (DER), formato OpenSSL
    huella_llave_publica: str    # SHA-256 de la llave pública (SPKI, DER)
    pem_privada_cifrada: bytes   # PRIVADA: no entregar
    p12: bytes                   # PRIVADA: no entregar
    pem_publica: bytes           # pública: se puede entregar
    pem_certificado: bytes       # pública: se puede entregar
    comandos_openssl: str = field(default="")


def generar_identidad(nombre: str, organizacion: str = "", pais: str = "BO", correo: str = "",
                      dias: int = 365, bits: int = 2048, contrasena: str = "") -> Identidad:
    """Genera un par RSA + certificado autofirmado + archivo .p12 protegido con contraseña."""
    nombre = _validar_texto(nombre, "El nombre", minimo=2)
    organizacion = _validar_texto(organizacion, "La organización", maximo=64)
    pais = (pais or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", pais):
        raise ErrorFirma("El país debe ser un código de 2 letras (por ejemplo, BO).")
    correo = (correo or "").strip()
    if correo and not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", correo):
        raise ErrorFirma("El correo electrónico no tiene un formato válido.")
    try:
        dias = int(dias)
        bits = int(bits)
    except (TypeError, ValueError):
        raise ErrorFirma("La validez y el tamaño de llave deben ser números.")
    if not 1 <= dias <= 3650:
        raise ErrorFirma("La validez debe estar entre 1 y 3650 días.")
    if bits not in TAMANOS_RSA:
        raise ErrorFirma("El tamaño de llave debe ser 2048 o 3072 bits.")
    if not contrasena or len(contrasena) < 8:
        raise ErrorFirma("La contraseña debe tener al menos 8 caracteres.")
    if len(contrasena) > 128:
        raise ErrorFirma("La contraseña no puede superar 128 caracteres.")

    # --- Par de llaves RSA (el exponente público 65537 es el estándar) ---
    llave = rsa.generate_private_key(public_exponent=65537, key_size=bits)

    # --- Certificado X.509 autofirmado (emisor = sujeto) ---
    atributos = [x509.NameAttribute(NameOID.COUNTRY_NAME, pais)]
    if organizacion:
        atributos.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organizacion))
    atributos.append(x509.NameAttribute(NameOID.COMMON_NAME, nombre))
    if correo:
        atributos.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, correo))
    sujeto = x509.Name(atributos)
    ahora = datetime.datetime.now(datetime.timezone.utc)
    desde = ahora - datetime.timedelta(minutes=5)     # margen por diferencias de reloj
    hasta = ahora + datetime.timedelta(days=dias)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(sujeto)
        .issuer_name(sujeto)
        .public_key(llave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(desde)
        .not_valid_after(hasta)
        # CA=TRUE permite que quien lo reciba lo marque como "raíz de confianza" (autofirmado).
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        # Usos permitidos: firmar documentos (digitalSignature, nonRepudiation) y firmar el propio certificado.
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(llave.public_key()), critical=False)
        .sign(llave, hashes.SHA256())
    )

    clave_bytes = contrasena.encode("utf-8")
    cifrado = serialization.BestAvailableEncryption(clave_bytes)
    pem_privada = llave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, cifrado)
    pem_publica = llave.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    pem_cert = certificado.public_bytes(serialization.Encoding.PEM)
    p12 = pkcs12.serialize_key_and_certificates(nombre.encode("utf-8"), llave, certificado, None, cifrado)
    spki = llave.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    sujeto_openssl = "/C=%s%s/CN=%s%s" % (
        pais, f"/O={organizacion}" if organizacion else "", nombre, f"/emailAddress={correo}" if correo else "")
    comandos = "\n".join([
        f"openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:{bits} -aes-256-cbc -out privada_cifrada.pem",
        "openssl pkey -in privada_cifrada.pem -pubout -out publica.pem",
        f'openssl req -new -x509 -utf8 -sha256 -days {dias} -key privada_cifrada.pem -subj "{sujeto_openssl}" '
        '-addext "basicConstraints=critical,CA:TRUE,pathlen:0" '
        '-addext "keyUsage=critical,digitalSignature,nonRepudiation,keyCertSign" -out certificado.pem',
        f'openssl pkcs12 -export -inkey privada_cifrada.pem -in certificado.pem -name "{nombre}" -out identidad.p12',
        "openssl x509 -in certificado.pem -noout -fingerprint -sha256",
    ])
    return Identidad(
        nombre=nombre, sujeto=certificado.subject.rfc4514_string().replace("1.2.840.113549.1.9.1=", "emailAddress="), bits=bits,
        serie_hex=format(certificado.serial_number, "x"), valido_desde=desde, valido_hasta=hasta,
        huella_certificado=_formato_huella(certificado.public_bytes(serialization.Encoding.DER)),
        huella_llave_publica=_formato_huella(spki),
        pem_privada_cifrada=pem_privada, p12=p12, pem_publica=pem_publica, pem_certificado=pem_cert,
        comandos_openssl=comandos)


# ---------------------------------------------------------------------------
# 2) FIRMA DE UN PDF
# ---------------------------------------------------------------------------
@dataclass
class ResultadoFirma:
    pdf_firmado: bytes
    campo: str
    firmante: str
    huella_certificado: str
    sha256_antes: str
    sha256_despues: str
    firmas_totales: int
    visible: bool
    fecha_utc: datetime.datetime


def _es_pdf(datos: bytes) -> bool:
    return datos[:1024].lstrip().startswith(b"%PDF-")


def firmar_pdf(pdf: bytes, p12: bytes, contrasena: str, motivo: str = "", lugar: str = "",
               visible: bool = True, pagina: int = None) -> ResultadoFirma:
    """Firma un PDF con la identidad (.p12). `pagina` es 1-based; None = última página."""
    if not pdf or not _es_pdf(pdf):
        raise ErrorFirma("El archivo seleccionado no es un PDF válido.")
    if not p12:
        raise ErrorFirma("Falta el archivo de identidad (.p12).")
    motivo = _solo_latin1(_validar_texto(motivo, "El motivo", maximo=100))
    lugar = _solo_latin1(_validar_texto(lugar, "El lugar", maximo=100))

    # Cargar la identidad: una contraseña incorrecta o un archivo dañado dan el mismo error.
    try:
        firmante_pyhanko = signers.SimpleSigner.load_pkcs12_data(
            p12, other_certs=[], passphrase=contrasena.encode("utf-8") if contrasena else None)
    except Exception:
        raise ErrorFirma("No se pudo abrir la identidad: contraseña incorrecta o archivo .p12 inválido.")
    if firmante_pyhanko is None:
        raise ErrorFirma("No se pudo abrir la identidad: contraseña incorrecta o archivo .p12 inválido.")
    cert = firmante_pyhanko.signing_cert
    ahora = datetime.datetime.now(datetime.timezone.utc)
    validez = cert["tbs_certificate"]["validity"]
    if ahora < validez["not_before"].native:
        raise ErrorFirma("El certificado todavía no es válido (revisa la fecha y hora de tu computadora).")
    if ahora > validez["not_after"].native:
        raise ErrorFirma("El certificado está vencido.")
    cn = cert.subject.native.get("common_name", "firmante")

    # Abrir el PDF y contar firmas previas (para elegir el campo y la posición visible).
    try:
        lector = PdfFileReader(io.BytesIO(pdf))
        previas = len(lector.embedded_signatures)
        escritor = IncrementalPdfFileWriter(io.BytesIO(pdf))
    except Exception:
        raise ErrorFirma("No se pudo leer el PDF (¿está protegido con contraseña o dañado?).")

    campo = f"Firma{previas + 1}_{nombre_seguro(cn)}"[:60]
    meta = signers.PdfSignatureMetadata(field_name=campo, reason=motivo or None, location=lugar or None)
    estilo = None
    spec = None
    if visible:
        indice = -1 if pagina is None else int(pagina) - 1
        try:
            pag_ref = lector.find_page_for_modification(indice)[0]
            caja = [float(x) for x in pag_ref.get_object()["/MediaBox"]]
            ancho, alto = caja[2] - caja[0], caja[3] - caja[1]
        except Exception:
            raise ErrorFirma("El número de página indicado no existe en el PDF.")
        # Dos recuadros por fila (izquierda, derecha); las firmas siguientes suben una fila.
        margen, ancho_caja, alto_caja = 56, min(240, (ancho - 3 * 56) / 2), 90
        columna, fila = previas % 2, previas // 2
        x0 = margen if columna == 0 else ancho - margen - ancho_caja
        y0 = 110 + fila * (alto_caja + 10)
        if y0 + alto_caja > alto:
            raise ErrorFirma("No hay espacio en la página para otro recuadro de firma visible.")
        spec = fields.SigFieldSpec(sig_field_name=campo, on_page=indice,
                                   box=(int(x0), int(y0), int(x0 + ancho_caja), int(y0 + alto_caja)))
        lineas = ["Firmado digitalmente por:", "%(signer)s", "Fecha: %(fecha)s"]
        if motivo:
            lineas.append("Motivo: %(motivo)s")
        if lugar:
            lineas.append("Lugar: %(lugar)s")
        estilo = TextStampStyle(stamp_text="\n".join(lineas), border_width=1,
                                border_color=(0.12, 0.23, 0.37))
    try:
        firmador = signers.PdfSigner(meta, signer=firmante_pyhanko, stamp_style=estilo, new_field_spec=spec)
        fecha_local = ahora.astimezone(BOLIVIA).strftime("%d/%m/%Y %H:%M:%S") + " (UTC-4)"
        salida = firmador.sign_pdf(
            escritor, appearance_text_params={"fecha": fecha_local, "motivo": motivo, "lugar": lugar})
    except ErrorFirma:
        raise
    except Exception as e:
        raise ErrorFirma(f"No se pudo firmar el PDF: {e}")
    firmado = salida.getvalue()
    return ResultadoFirma(
        pdf_firmado=firmado, campo=campo, firmante=cn,
        huella_certificado=_formato_huella(cert.dump()),
        sha256_antes=hashlib.sha256(pdf).hexdigest(), sha256_despues=hashlib.sha256(firmado).hexdigest(),
        firmas_totales=previas + 1, visible=bool(visible), fecha_utc=ahora)


# ---------------------------------------------------------------------------
# 3) VALIDACIÓN DE FIRMAS
# ---------------------------------------------------------------------------
@dataclass
class FirmaValidada:
    campo: str
    firmante: str
    sujeto: str
    emisor: str
    huella_certificado: str
    algoritmo_hash: str
    fecha_firma: datetime.datetime
    intacta: bool            # el contenido firmado NO cambió
    valida: bool             # la firma criptográfica es correcta
    confiable: bool          # el certificado es de confianza (o la llave pública coincide)
    como_confia: str         # explicación de la confianza
    cobertura: str
    modificaciones: str
    estado: str              # "valida" | "no_confiable" | "alterada"
    veredicto: str
    detalle_tecnico: str


@dataclass
class ResultadoValidacion:
    sha256_documento: str
    firmas: list
    estado_global: str
    mensaje: str


_COBERTURA = {
    "ENTIRE_FILE": "Cubre todo el archivo (no hubo cambios posteriores).",
    "ENTIRE_REVISION": "Cubre su revisión del documento; después se añadieron cambios (por ejemplo, otras firmas).",
    "CONTIGUOUS_BLOCK_FROM_START": "Cubre solo un bloque inicial del archivo.",
    "UNCLEAR": "La cobertura de la firma no es clara.",
}
_MODIFICACION = {
    ModificationLevel.NONE: "Sin modificaciones posteriores.",
    ModificationLevel.LTA_UPDATES: "Solo actualizaciones de validación a largo plazo (permitidas).",
    ModificationLevel.FORM_FILLING: "Solo se añadieron firmas o campos de formulario (permitido).",
    ModificationLevel.ANNOTATIONS: "Se añadieron anotaciones después de firmar.",
    ModificationLevel.OTHER: "El documento fue modificado después de firmar.",
}


def _cargar_confianzas(archivos):
    """Separa lo que sube el usuario en certificados (raíces de confianza) y llaves públicas."""
    certificados, llaves_spki = [], []
    for datos in archivos or []:
        if not datos:
            continue
        leido = False
        try:
            for c in x509.load_pem_x509_certificates(datos):
                certificados.append(asn1_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER)))
                leido = True
        except Exception:
            pass
        if not leido:
            try:
                c = x509.load_der_x509_certificate(datos)
                certificados.append(asn1_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER)))
                leido = True
            except Exception:
                pass
        if not leido:
            try:
                k = serialization.load_pem_public_key(datos)
                llaves_spki.append(k.public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
                leido = True
            except Exception:
                pass
        if not leido:
            raise ErrorFirma("Uno de los archivos de confianza no es un certificado ni una llave pública en formato PEM.")
    return certificados, llaves_spki


def validar_pdf(pdf: bytes, confianzas=None) -> ResultadoValidacion:
    """Valida todas las firmas de un PDF. `confianzas` = lista de bytes de certificados .pem
    (raíces de confianza) o de llaves públicas .pem."""
    if not pdf or not _es_pdf(pdf):
        raise ErrorFirma("El archivo seleccionado no es un PDF válido.")
    certificados, llaves_spki = _cargar_confianzas(confianzas)
    try:
        lector = PdfFileReader(io.BytesIO(pdf))
        firmas_pdf = list(lector.embedded_signatures)
    except Exception:
        raise ErrorFirma("No se pudo leer el PDF (¿está protegido con contraseña o dañado?).")
    huella_doc = hashlib.sha256(pdf).hexdigest()
    if not firmas_pdf:
        return ResultadoValidacion(huella_doc, [], "sin_firmas", "Este PDF no contiene ninguna firma digital.")

    contexto = ValidationContext(trust_roots=certificados or None, allow_fetching=False)
    resultados = []
    for posicion, sig in enumerate(firmas_pdf):
        es_ultima = posicion == len(firmas_pdf) - 1
        try:
            st = validate_pdf_signature(sig, contexto)
        except Exception as e:
            resultados.append(FirmaValidada(
                sig.field_name, "(desconocido)", "", "", "", "", datetime.datetime.now(datetime.timezone.utc),
                False, False, False, "", "", "No se pudo validar la firma.", "alterada",
                "NO SE PUDO VALIDAR (la firma está dañada o es de un tipo no soportado)", str(e)))
            continue
        cert = sig.signer_cert
        spki_firmante = cert.public_key.dump()
        # Una llave pública .pem entregada por el firmante también sirve para confirmar su identidad.
        coincide_llave = any(spki_firmante == k_der or _spki_igual(spki_firmante, k_der) for k_der in llaves_spki)
        if st.trusted:
            confiable, como = True, "El certificado del firmante coincide con un certificado de confianza proporcionado."
        elif coincide_llave:
            confiable, como = True, "La llave pública del firmante coincide con la llave pública proporcionada."
        else:
            confiable, como = False, ("No se proporcionó ningún certificado ni llave pública de confianza que "
                                      "respalde a este firmante (certificado autofirmado).")
        nivel = st.modification_level or ModificationLevel.NONE
        mod_ok = nivel in (ModificationLevel.NONE, ModificationLevel.LTA_UPDATES, ModificationLevel.FORM_FILLING)
        texto_modificaciones = _MODIFICACION.get(nivel, str(nivel))
        # La ÚLTIMA firma debe cubrir TODO el archivo: si hay bytes después de ella que no son otra firma,
        # alguien añadió contenido sin firmar y el documento ya no es íntegro.
        if es_ultima and st.coverage.name != "ENTIRE_FILE":
            mod_ok = False
            texto_modificaciones = "Hay datos añadidos al final del archivo que no están cubiertos por ninguna firma."
        if not st.intact or not st.valid or not mod_ok:
            estado = "alterada"
            veredicto = ("FIRMA NO VÁLIDA: el documento fue modificado después de firmarse."
                         if (not st.intact or not mod_ok) else "FIRMA NO VÁLIDA: la firma criptográfica es incorrecta.")
        elif confiable:
            estado, veredicto = "valida", "FIRMA VÁLIDA: el documento está íntegro y la identidad del firmante está confirmada."
        else:
            estado = "no_confiable"
            veredicto = ("FIRMA ÍNTEGRA, IDENTIDAD NO CONFIRMADA: el documento no fue alterado, "
                         "pero no se confía en el certificado del firmante.")
        resultados.append(FirmaValidada(
            campo=sig.field_name, firmante=cert.subject.native.get("common_name", "(sin nombre)"),
            sujeto=cert.subject.human_friendly, emisor=cert.issuer.human_friendly,
            huella_certificado=_formato_huella(cert.dump()), algoritmo_hash=str(sig.md_algorithm).upper(),
            fecha_firma=st.signer_reported_dt, intacta=bool(st.intact), valida=bool(st.valid),
            confiable=confiable, como_confia=como,
            cobertura=_COBERTURA.get(st.coverage.name, st.coverage.name),
            modificaciones=texto_modificaciones, estado=estado, veredicto=veredicto,
            detalle_tecnico=st.summary()))
    estados = {r.estado for r in resultados}
    if estados == {"valida"}:
        glob, msg = "valida", "Todas las firmas son válidas."
    elif "alterada" in estados:
        glob, msg = "alterada", "Hay firmas NO válidas: el documento fue alterado o la firma está dañada."
    else:
        glob, msg = "no_confiable", ("Todas las firmas son íntegras, pero la identidad de al menos un firmante "
                                     "no está confirmada (falta el certificado de confianza).")
    return ResultadoValidacion(huella_doc, resultados, glob, msg)


def _spki_igual(a: bytes, b: bytes) -> bool:
    """Compara dos llaves públicas SPKI ignorando diferencias de codificación equivalentes."""
    try:
        ka = serialization.load_der_public_key(a)
        kb = serialization.load_der_public_key(b)
        return ka.public_numbers() == kb.public_numbers()
    except Exception:
        return False
