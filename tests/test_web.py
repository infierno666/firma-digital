# -*- coding: utf-8 -*-
"""Pruebas de la aplicación web: se recorre el flujo completo por HTTP (generar -> firmar -> validar)."""
import base64
import io
import re
import unittest

from utiles import pdf_minimo
import app as aplicacion

PW_A, PW_B = "clave-segura-1", "otra-clave-123"


def _extraer_archivos(html: str) -> dict:
    """Lee los enlaces de descarga (data URLs) de la página de resultados de generación."""
    archivos = {}
    for url, nombre in re.findall(r'href="data:[^;]+;base64,([^"]+)" download="([^"]+)"', html):
        archivos[nombre] = base64.b64decode(url)
    return archivos


class PruebasWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        aplicacion.app.config["TESTING"] = True
        cls.c = aplicacion.app.test_client()
        cls.pdf = pdf_minimo(3)

    def _generar(self, nombre, pw):
        r = self.c.post("/generar", data=dict(nombre=nombre, organizacion="Universidad Domingo Savio", pais="BO",
                                              correo="", bits="2048", dias="365", contrasena=pw, contrasena2=pw))
        self.assertEqual(r.status_code, 200)
        return _extraer_archivos(r.get_data(as_text=True)), r.get_data(as_text=True)

    def _firmar(self, pdf, p12, pw, nombre="informe.pdf"):
        r = self.c.post("/firmar", data=dict(pdf=(io.BytesIO(pdf), nombre), p12=(io.BytesIO(p12), "i.p12"),
                                             contrasena=pw, motivo="Informe A5", lugar="Cochabamba", visible="on"),
                        content_type="multipart/form-data")
        return r

    def test_paginas_principales(self):
        for ruta in ("/", "/generar", "/firmar", "/validar"):
            r = self.c.get(ruta)
            self.assertEqual(r.status_code, 200, ruta)
            self.assertEqual(r.headers["Cache-Control"], "no-store")
            self.assertIn("Firma Digital", r.get_data(as_text=True))

    def test_generar_entrega_los_cuatro_archivos_y_el_zip(self):
        archivos, html = self._generar("Daniel Maldonado Céspedes", PW_A)
        nombres = set(archivos)
        self.assertIn("publica_daniel_maldonado_cespedes.pem", nombres)
        self.assertIn("certificado_daniel_maldonado_cespedes.pem", nombres)
        self.assertIn("privada_cifrada_daniel_maldonado_cespedes.pem", nombres)
        self.assertIn("identidad_daniel_maldonado_cespedes.p12", nombres)
        self.assertIn("llaves_publicas_daniel_maldonado_cespedes.zip", nombres)
        self.assertTrue(archivos["publica_daniel_maldonado_cespedes.pem"].startswith(b"-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(archivos["certificado_daniel_maldonado_cespedes.pem"].startswith(b"-----BEGIN CERTIFICATE-----"))
        self.assertIn(b"ENCRYPTED PRIVATE KEY", archivos["privada_cifrada_daniel_maldonado_cespedes.pem"])
        self.assertIn("openssl genpkey", html)
        self.assertIn("NO entregar", html)
        # el zip público no debe contener nada privado
        import zipfile
        z = zipfile.ZipFile(io.BytesIO(archivos["llaves_publicas_daniel_maldonado_cespedes.zip"]))
        self.assertEqual(sorted(z.namelist()), ["certificado_daniel_maldonado_cespedes.pem", "publica_daniel_maldonado_cespedes.pem"])
        self.assertNotIn(b"PRIVATE KEY", b"".join(z.read(n) for n in z.namelist()))

    def test_generar_errores(self):
        casos = [dict(nombre="Ana", contrasena="corta", contrasena2="corta"),
                 dict(nombre="Ana", contrasena="una-clave-1", contrasena2="otra-clave-2"),
                 dict(nombre="", contrasena="una-clave-1", contrasena2="una-clave-1")]
        for c in casos:
            r = self.c.post("/generar", data=dict(pais="BO", bits="2048", dias="365", **c))
            self.assertEqual(r.status_code, 400, c)
            self.assertIn("aviso rojo", r.get_data(as_text=True))

    def test_flujo_completo_dos_firmantes(self):
        a, _ = self._generar("Daniel Maldonado Céspedes", PW_A)
        b, _ = self._generar("Leonardo Nogales Torres", PW_B)
        # --- primera firma
        r = self._firmar(self.pdf, a["identidad_daniel_maldonado_cespedes.p12"], PW_A)
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("Documento firmado correctamente", html)
        enlace = re.search(r'href="(/descargar/[^"]+)"', html).group(1)
        d = self.c.get(enlace)
        self.assertEqual(d.status_code, 200)
        self.assertEqual(d.mimetype, "application/pdf")
        self.assertIn("informe_firmado.pdf", d.headers["Content-Disposition"])
        firmado1 = d.data
        # --- segunda firma sobre el PDF ya firmado
        r = self._firmar(firmado1, b["identidad_leonardo_nogales_torres.p12"], PW_B, nombre="informe_firmado.pdf")
        html = r.get_data(as_text=True)
        self.assertIn("Firmas en el documento</th><td>2", html)
        enlace = re.search(r'href="(/descargar/[^"]+)"', html).group(1)
        d = self.c.get(enlace)
        self.assertIn("informe_firmado2.pdf", d.headers["Content-Disposition"])
        firmado2 = d.data
        # --- validar sin confianza
        r = self.c.post("/validar", data=dict(pdf=(io.BytesIO(firmado2), "x.pdf")), content_type="multipart/form-data")
        html = r.get_data(as_text=True)
        self.assertIn("IDENTIDAD NO CONFIRMADA", html)
        self.assertEqual(html.count('class="firma ambar"'), 2)
        # --- validar con los certificados
        r = self.c.post("/validar", content_type="multipart/form-data", data=dict(
            pdf=(io.BytesIO(firmado2), "x.pdf"),
            confianzas=[(io.BytesIO(a["certificado_daniel_maldonado_cespedes.pem"]), "a.pem"),
                        (io.BytesIO(b["certificado_leonardo_nogales_torres.pem"]), "b.pem")]))
        html = r.get_data(as_text=True)
        self.assertIn("Todas las firmas son válidas", html)
        self.assertEqual(html.count('class="firma verde"'), 2)
        self.assertIn("Daniel Maldonado Céspedes", html)
        self.assertIn("Leonardo Nogales Torres", html)
        # --- validar con las llaves públicas
        r = self.c.post("/validar", content_type="multipart/form-data", data=dict(
            pdf=(io.BytesIO(firmado2), "x.pdf"),
            confianzas=[(io.BytesIO(a["publica_daniel_maldonado_cespedes.pem"]), "a.pem"),
                        (io.BytesIO(b["publica_leonardo_nogales_torres.pem"]), "b.pem")]))
        self.assertIn("Todas las firmas son válidas", r.get_data(as_text=True))
        # --- documento alterado
        alterado = bytearray(firmado2)
        alterado[alterado.index(b"Pagina 1") + 3] ^= 1
        r = self.c.post("/validar", data=dict(pdf=(io.BytesIO(bytes(alterado)), "x.pdf")), content_type="multipart/form-data")
        html = r.get_data(as_text=True)
        self.assertIn("NO válidas", html)
        self.assertIn('class="firma rojo"', html)

    def test_errores_al_firmar(self):
        a, _ = self._generar("Ana Pérez", PW_A)
        p12 = a["identidad_ana_perez.p12"]
        r = self._firmar(self.pdf, p12, "contraseña-mala")
        self.assertEqual(r.status_code, 400)
        self.assertIn("contraseña incorrecta", r.get_data(as_text=True))
        r = self._firmar(b"no soy un pdf", p12, PW_A)
        self.assertEqual(r.status_code, 400)
        self.assertIn("no es un PDF válido", r.get_data(as_text=True))
        r = self.c.post("/firmar", data=dict(contrasena=PW_A), content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Selecciona el PDF", r.get_data(as_text=True))
        r = self.c.post("/firmar", content_type="multipart/form-data", data=dict(
            pdf=(io.BytesIO(self.pdf), "a.pdf"), p12=(io.BytesIO(p12), "a.p12"), contrasena=PW_A, pagina="abc"))
        self.assertEqual(r.status_code, 400)

    def test_errores_al_validar(self):
        r = self.c.post("/validar", data={}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)
        r = self.c.post("/validar", data=dict(pdf=(io.BytesIO(b"hola"), "x.pdf")), content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)
        r = self.c.post("/validar", data=dict(pdf=(io.BytesIO(self.pdf), "x.pdf")), content_type="multipart/form-data")
        self.assertIn("no contiene ninguna firma digital", r.get_data(as_text=True))
        r = self.c.post("/validar", content_type="multipart/form-data", data=dict(
            pdf=(io.BytesIO(self.pdf), "x.pdf"), confianzas=[(io.BytesIO(b"basura"), "x.pem")]))
        self.assertEqual(r.status_code, 400)

    def test_descarga_inexistente_y_archivo_demasiado_grande(self):
        self.assertEqual(self.c.get("/descargar/no-existe").status_code, 404)
        limite = aplicacion.app.config["MAX_CONTENT_LENGTH"]
        aplicacion.app.config["MAX_CONTENT_LENGTH"] = 1000
        try:
            r = self.c.post("/validar", data=dict(pdf=(io.BytesIO(b"%PDF-" + b"0" * 5000), "x.pdf")), content_type="multipart/form-data")
            self.assertEqual(r.status_code, 413)
        finally:
            aplicacion.app.config["MAX_CONTENT_LENGTH"] = limite

    def test_la_aplicacion_no_registra_contraseñas(self):
        import logging
        flujo = io.StringIO()
        manejador = logging.StreamHandler(flujo)
        logging.getLogger().addHandler(manejador)
        try:
            self._generar("Sin Registro", "contrasena-secreta-xyz")
        finally:
            logging.getLogger().removeHandler(manejador)
        self.assertNotIn("contrasena-secreta-xyz", flujo.getvalue())


if __name__ == "__main__":
    unittest.main()
