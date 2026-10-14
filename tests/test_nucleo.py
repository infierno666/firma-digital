# -*- coding: utf-8 -*-
"""Pruebas del núcleo criptográfico (firma_digital.py)."""
import datetime
import os
import shutil
import subprocess
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from utiles import pdf_minimo
import firma_digital as fd

PW_A, PW_B = "clave-segura-1", "otra-clave-123"


def _w(ruta, datos):
    with open(ruta, "wb") as f:
        f.write(datos)


def _r(ruta):
    with open(ruta, "rb") as f:
        return f.read()


class PruebasGeneracion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = fd.generar_identidad("Daniel Maldonado Céspedes", "Universidad Domingo Savio", "bo",
                                     "daniel@ejemplo.com", 365, 2048, PW_A)

    def test_certificado_contenido(self):
        cert = x509.load_pem_x509_certificate(self.a.pem_certificado)
        self.assertEqual(cert.public_key().key_size, 2048)
        self.assertEqual(cert.subject, cert.issuer)                                   # autofirmado
        self.assertEqual(cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value,
                         "Daniel Maldonado Céspedes")                                  # tildes
        self.assertEqual(cert.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value, "BO")
        self.assertEqual(cert.signature_hash_algorithm.name, "sha256")
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.digital_signature and ku.content_commitment)
        self.assertTrue(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)

    def test_validez(self):
        cert = x509.load_pem_x509_certificate(self.a.pem_certificado)
        dias = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        self.assertIn(dias, (364, 365))

    def test_llave_publica_coincide_con_el_certificado(self):
        cert = x509.load_pem_x509_certificate(self.a.pem_certificado)
        pub = serialization.load_pem_public_key(self.a.pem_publica)
        self.assertEqual(cert.public_key().public_numbers(), pub.public_numbers())

    def test_llave_privada_esta_cifrada(self):
        self.assertIn(b"ENCRYPTED PRIVATE KEY", self.a.pem_privada_cifrada)
        with self.assertRaises(TypeError):
            serialization.load_pem_private_key(self.a.pem_privada_cifrada, password=None)
        llave = serialization.load_pem_private_key(self.a.pem_privada_cifrada, PW_A.encode())
        self.assertEqual(llave.key_size, 2048)

    def test_p12_protegido_con_contraseña(self):
        llave, cert, _ = pkcs12.load_key_and_certificates(self.a.p12, PW_A.encode())
        self.assertIsNotNone(llave)
        with self.assertRaises(ValueError):
            pkcs12.load_key_and_certificates(self.a.p12, b"incorrecta")

    def test_huella_coincide_con_el_certificado(self):
        cert = x509.load_pem_x509_certificate(self.a.pem_certificado)
        import hashlib
        h = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
        self.assertEqual(self.a.huella_certificado, ":".join(h[i:i + 2] for i in range(0, 64, 2)))

    def test_dos_identidades_son_distintas(self):
        b = fd.generar_identidad("Leonardo Nogales Torres", "", "BO", "", 30, 2048, PW_B)
        self.assertNotEqual(self.a.huella_certificado, b.huella_certificado)
        self.assertNotEqual(self.a.huella_llave_publica, b.huella_llave_publica)

    def test_llave_de_3072_bits(self):
        c = fd.generar_identidad("Prueba Tres", "", "BO", "", 10, 3072, PW_A)
        self.assertEqual(x509.load_pem_x509_certificate(c.pem_certificado).public_key().key_size, 3072)

    def test_validaciones_de_entrada(self):
        casos = [
            dict(nombre="", contrasena=PW_A), dict(nombre="A", contrasena=PW_A),
            dict(nombre="Ana", contrasena="corta"), dict(nombre="Ana", contrasena=PW_A, pais="BOL"),
            dict(nombre="Ana", contrasena=PW_A, pais="1B"), dict(nombre="Ana", contrasena=PW_A, correo="no-es-correo"),
            dict(nombre="Ana", contrasena=PW_A, dias=0), dict(nombre="Ana", contrasena=PW_A, dias=99999),
            dict(nombre="Ana", contrasena=PW_A, dias="abc"), dict(nombre="Ana", contrasena=PW_A, bits=1024),
            dict(nombre="Ana\x00", contrasena=PW_A), dict(nombre="x" * 100, contrasena=PW_A),
        ]
        for c in casos:
            with self.subTest(c=c), self.assertRaises(fd.ErrorFirma):
                fd.generar_identidad(**c)

    def test_comandos_openssl_incluyen_los_datos(self):
        self.assertIn("rsa_keygen_bits:2048", self.a.comandos_openssl)
        self.assertIn("Daniel Maldonado Céspedes", self.a.comandos_openssl)
        self.assertIn("openssl pkcs12 -export", self.a.comandos_openssl)

    def test_nombre_seguro(self):
        self.assertEqual(fd.nombre_seguro("José Pérez Ñandú"), "jose_perez_nandu")
        self.assertEqual(fd.nombre_seguro("***"), "firmante")


class PruebasFirmaYValidacion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = fd.generar_identidad("Daniel Maldonado Céspedes", "Universidad Domingo Savio", "BO", "", 365, 2048, PW_A)
        cls.b = fd.generar_identidad("Leonardo Nogales Torres", "Universidad Domingo Savio", "BO", "", 365, 2048, PW_B)
        cls.pdf = pdf_minimo(3)

    def test_firmar_y_validar_sin_confianza(self):
        r = fd.firmar_pdf(self.pdf, self.a.p12, PW_A, "Informe A5", "Cochabamba")
        self.assertEqual(r.firmas_totales, 1)
        self.assertNotEqual(r.sha256_antes, r.sha256_despues)
        v = fd.validar_pdf(r.pdf_firmado)
        self.assertEqual(v.estado_global, "no_confiable")
        f = v.firmas[0]
        self.assertTrue(f.intacta and f.valida)
        self.assertFalse(f.confiable)
        self.assertEqual(f.firmante, "Daniel Maldonado Céspedes")
        self.assertEqual(f.algoritmo_hash, "SHA256")
        self.assertEqual(f.huella_certificado, self.a.huella_certificado)

    def test_validar_con_certificado_de_confianza(self):
        r = fd.firmar_pdf(self.pdf, self.a.p12, PW_A)
        v = fd.validar_pdf(r.pdf_firmado, [self.a.pem_certificado])
        self.assertEqual(v.estado_global, "valida")
        self.assertTrue(v.firmas[0].confiable)

    def test_validar_con_llave_publica(self):
        r = fd.firmar_pdf(self.pdf, self.a.p12, PW_A)
        v = fd.validar_pdf(r.pdf_firmado, [self.a.pem_publica])
        self.assertEqual(v.estado_global, "valida")
        self.assertIn("llave pública", v.firmas[0].como_confia)

    def test_confiar_en_otro_certificado_no_valida(self):
        r = fd.firmar_pdf(self.pdf, self.a.p12, PW_A)
        v = fd.validar_pdf(r.pdf_firmado, [self.b.pem_certificado])
        self.assertEqual(v.estado_global, "no_confiable")
        v = fd.validar_pdf(r.pdf_firmado, [self.b.pem_publica])
        self.assertEqual(v.estado_global, "no_confiable")

    def test_doble_firma_conserva_la_primera(self):
        r1 = fd.firmar_pdf(self.pdf, self.a.p12, PW_A)
        r2 = fd.firmar_pdf(r1.pdf_firmado, self.b.p12, PW_B)
        self.assertEqual(r2.firmas_totales, 2)
        v = fd.validar_pdf(r2.pdf_firmado, [self.a.pem_certificado, self.b.pem_certificado])
        self.assertEqual(v.estado_global, "valida")
        self.assertEqual([f.firmante for f in v.firmas], ["Daniel Maldonado Céspedes", "Leonardo Nogales Torres"])
        self.assertTrue(all(f.intacta and f.valida and f.confiable for f in v.firmas))
        # solo una de las dos es confiable -> el global baja a "no_confiable"
        v = fd.validar_pdf(r2.pdf_firmado, [self.a.pem_certificado])
        self.assertEqual(v.estado_global, "no_confiable")
        self.assertEqual([f.estado for f in v.firmas], ["valida", "no_confiable"])

    def test_manipulacion_se_detecta(self):
        r = fd.firmar_pdf(self.pdf, self.a.p12, PW_A)
        datos = bytearray(r.pdf_firmado)
        datos[datos.index(b"Pagina 1") + 3] ^= 0x01                 # cambia el contenido firmado
        v = fd.validar_pdf(bytes(datos), [self.a.pem_certificado])
        self.assertEqual(v.estado_global, "alterada")
        self.assertFalse(v.firmas[0].intacta)

    def test_contenido_agregado_despues_de_firmar_se_detecta(self):
        r = fd.firmar_pdf(self.pdf, self.a.p12, PW_A)
        v = fd.validar_pdf(r.pdf_firmado + b"\n% texto anadido\n", [self.a.pem_certificado])
        self.assertNotEqual(v.estado_global, "valida")

    def test_firma_invisible_y_pagina_elegida(self):
        r = fd.firmar_pdf(self.pdf, self.a.p12, PW_A, visible=False)
        self.assertFalse(r.visible)
        self.assertEqual(fd.validar_pdf(r.pdf_firmado, [self.a.pem_certificado]).estado_global, "valida")
        r = fd.firmar_pdf(self.pdf, self.a.p12, PW_A, visible=True, pagina=1)
        self.assertEqual(fd.validar_pdf(r.pdf_firmado, [self.a.pem_certificado]).estado_global, "valida")
        with self.assertRaises(fd.ErrorFirma):
            fd.firmar_pdf(self.pdf, self.a.p12, PW_A, visible=True, pagina=99)

    def test_la_firma_visible_aparece_en_el_texto_de_la_pagina(self):
        if not shutil.which("pdftotext"):
            self.skipTest("pdftotext no está instalado")
        r = fd.firmar_pdf(self.pdf, self.a.p12, PW_A, "Informe A5", "Cochabamba")
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as t:
            t.write(r.pdf_firmado)
        try:
            texto = subprocess.run(["pdftotext", "-f", "3", "-l", "3", t.name, "-"], capture_output=True, text=True).stdout
        finally:
            os.remove(t.name)
        self.assertIn("Firmado digitalmente por", texto)
        self.assertIn("Daniel Maldonado Céspedes", texto)
        self.assertIn("Cochabamba", texto)

    def test_errores_de_firma(self):
        with self.assertRaises(fd.ErrorFirma):
            fd.firmar_pdf(self.pdf, self.a.p12, "contraseña-mala")
        with self.assertRaises(fd.ErrorFirma):
            fd.firmar_pdf(b"esto no es un pdf", self.a.p12, PW_A)
        with self.assertRaises(fd.ErrorFirma):
            fd.firmar_pdf(self.pdf, b"basura", PW_A)
        with self.assertRaises(fd.ErrorFirma):
            fd.firmar_pdf(b"", self.a.p12, PW_A)
        with self.assertRaises(fd.ErrorFirma):
            fd.firmar_pdf(self.pdf, b"", PW_A)

    def test_certificado_vencido_o_futuro_se_rechaza(self):
        from cryptography.hazmat.primitives import hashes
        llave = serialization.load_pem_private_key(self.a.pem_privada_cifrada, PW_A.encode())
        ahora = datetime.datetime.now(datetime.timezone.utc)
        nombre = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Vencido")])
        for desde, hasta in ((ahora - datetime.timedelta(days=10), ahora - datetime.timedelta(days=1)),
                             (ahora + datetime.timedelta(days=1), ahora + datetime.timedelta(days=5))):
            cert = (x509.CertificateBuilder().subject_name(nombre).issuer_name(nombre).public_key(llave.public_key())
                    .serial_number(1).not_valid_before(desde).not_valid_after(hasta).sign(llave, hashes.SHA256()))
            p12 = pkcs12.serialize_key_and_certificates(b"x", llave, cert, None, serialization.BestAvailableEncryption(b"clave-12345"))
            with self.assertRaises(fd.ErrorFirma):
                fd.firmar_pdf(self.pdf, p12, "clave-12345")

    def test_validar_errores(self):
        with self.assertRaises(fd.ErrorFirma):
            fd.validar_pdf(b"no es pdf")
        with self.assertRaises(fd.ErrorFirma):
            fd.validar_pdf(self.pdf, [b"esto no es un certificado"])
        v = fd.validar_pdf(self.pdf)
        self.assertEqual(v.estado_global, "sin_firmas")
        self.assertEqual(v.firmas, [])

    def test_certificado_en_formato_der_tambien_sirve(self):
        r = fd.firmar_pdf(self.pdf, self.a.p12, PW_A)
        der = x509.load_pem_x509_certificate(self.a.pem_certificado).public_bytes(serialization.Encoding.DER)
        self.assertEqual(fd.validar_pdf(r.pdf_firmado, [der]).estado_global, "valida")

    def test_cadena_de_dos_firmas_de_la_misma_persona(self):
        r1 = fd.firmar_pdf(self.pdf, self.a.p12, PW_A)
        r2 = fd.firmar_pdf(r1.pdf_firmado, self.a.p12, PW_A)
        self.assertEqual(len(fd.validar_pdf(r2.pdf_firmado).firmas), 2)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL no está instalado")
class PruebasInteroperabilidadOpenSSL(unittest.TestCase):
    """Verifica que lo que produce la aplicación coincide con lo que dice OpenSSL, y viceversa."""

    @classmethod
    def setUpClass(cls):
        cls.a = fd.generar_identidad("Daniel Maldonado Céspedes", "Universidad Domingo Savio", "BO", "", 365, 2048, PW_A)
        cls.pdf = pdf_minimo(2)

    def _openssl(self, *args, entrada=None):
        return subprocess.run(["openssl", *args], input=entrada, capture_output=True, check=True)

    def test_huella_del_certificado_coincide_con_openssl(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "c.pem")
            _w(ruta, self.a.pem_certificado)
            salida = self._openssl("x509", "-in", ruta, "-noout", "-fingerprint", "-sha256").stdout.decode()
        self.assertIn(self.a.huella_certificado, salida)

    def test_openssl_reconoce_el_certificado_como_autofirmado_valido(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "c.pem")
            _w(ruta, self.a.pem_certificado)
            salida = self._openssl("verify", "-CAfile", ruta, ruta).stdout.decode()
        self.assertIn("OK", salida)

    def test_llave_publica_pem_coincide_con_la_del_certificado(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "c.pem")
            _w(ruta, self.a.pem_certificado)
            pub = self._openssl("x509", "-in", ruta, "-pubkey", "-noout").stdout
        self.assertEqual(pub.strip(), self.a.pem_publica.strip())

    def test_openssl_puede_leer_el_p12_de_la_aplicacion(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "i.p12")
            _w(ruta, self.a.p12)
            salida = self._openssl("pkcs12", "-in", ruta, "-nokeys", "-passin", "pass:" + PW_A).stdout.decode("latin-1")
        self.assertIn("BEGIN CERTIFICATE", salida)

    def test_identidad_creada_con_openssl_firma_en_la_aplicacion(self):
        """Se ejecutan los mismos comandos que muestra la página (con contraseñas por parámetro)."""
        with tempfile.TemporaryDirectory() as d:
            p = lambda n: os.path.join(d, n)
            self._openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-aes-256-cbc",
                          "-pass", "pass:" + PW_B, "-out", p("privada_cifrada.pem"))
            self._openssl("pkey", "-in", p("privada_cifrada.pem"), "-passin", "pass:" + PW_B, "-pubout", "-out", p("publica.pem"))
            self._openssl("req", "-new", "-x509", "-utf8", "-sha256", "-days", "365", "-key", p("privada_cifrada.pem"),
                          "-passin", "pass:" + PW_B, "-subj", "/C=BO/O=Universidad Domingo Savio/CN=Leonardo Nogales Torres",
                          "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                          "-addext", "keyUsage=critical,digitalSignature,nonRepudiation,keyCertSign", "-out", p("certificado.pem"))
            self._openssl("pkcs12", "-export", "-inkey", p("privada_cifrada.pem"), "-in", p("certificado.pem"),
                          "-passin", "pass:" + PW_B, "-passout", "pass:" + PW_B, "-name", "Leonardo Nogales Torres",
                          "-out", p("identidad.p12"))
            p12 = _r(p("identidad.p12"))
            cert = _r(p("certificado.pem"))
            pub = _r(p("publica.pem"))
        r = fd.firmar_pdf(self.pdf, p12, PW_B)
        self.assertEqual(fd.validar_pdf(r.pdf_firmado, [cert]).estado_global, "valida")
        self.assertEqual(fd.validar_pdf(r.pdf_firmado, [pub]).estado_global, "valida")

    @unittest.skipUnless(shutil.which("pdfsig"), "pdfsig (poppler-utils) no está instalado")
    def test_pdfsig_confirma_la_firma(self):
        r = fd.firmar_pdf(self.pdf, self.a.p12, PW_A)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as t:
            t.write(r.pdf_firmado)
        try:
            salida = subprocess.run(["pdfsig", t.name], capture_output=True, text=True).stdout
            datos = bytearray(r.pdf_firmado)
            datos[datos.index(b"Pagina 1") + 3] ^= 1
            _w(t.name, datos)
            alterado = subprocess.run(["pdfsig", t.name], capture_output=True, text=True).stdout
        finally:
            os.remove(t.name)
        self.assertIn("Signature is Valid", salida)
        self.assertIn("Daniel Maldonado Céspedes", salida)
        self.assertNotIn("Signature is Valid", alterado)


if __name__ == "__main__":
    unittest.main()
