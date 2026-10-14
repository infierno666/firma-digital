# -*- coding: utf-8 -*-
"""
app.py  -  Aplicación web de firma digital de PDF (Actividad A5)
Seguridad Informática I · Universidad Domingo Savio

Páginas:
    /           Inicio
    /generar    1) Generar llaves (RSA) y certificado
    /firmar     2) Firmar un PDF con la llave privada
    /validar    3) Validar las firmas de un PDF

Toda la criptografía está en firma_digital.py; este archivo solo maneja la parte web.

Seguridad de diseño:
  * La aplicación corre SOLO en tu computadora (127.0.0.1).
  * No guarda llaves ni contraseñas en disco. Los PDF firmados se conservan en memoria
    unos minutos únicamente para poder descargarlos, y luego se borran.
  * Las respuestas llevan "Cache-Control: no-store" para que el navegador no guarde material sensible.
"""

import base64
import datetime
import io
import re
import secrets
import threading
import time
import zipfile

from flask import Flask, abort, render_template, request, send_file
from werkzeug.utils import secure_filename

import firma_digital as fd

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 60 * 1024 * 1024      # 60 MB

# --- Almacén temporal en memoria para las descargas de PDF firmados ---
_ALMACEN = {}
_CERROJO = threading.Lock()
_VIDA_SEGUNDOS = 15 * 60
_MAX_ENTRADAS = 20


def _guardar(datos: bytes, nombre: str, tipo: str) -> str:
    ahora = time.time()
    with _CERROJO:
        for t in [t for t, v in _ALMACEN.items() if v["vence"] < ahora]:
            del _ALMACEN[t]
        while len(_ALMACEN) >= _MAX_ENTRADAS:
            del _ALMACEN[min(_ALMACEN, key=lambda t: _ALMACEN[t]["vence"])]
        token = secrets.token_urlsafe(16)
        _ALMACEN[token] = {"datos": datos, "nombre": nombre, "tipo": tipo, "vence": ahora + _VIDA_SEGUNDOS}
    return token


def _data_url(datos: bytes, tipo: str) -> str:
    return f"data:{tipo};base64," + base64.b64encode(datos).decode("ascii")


@app.template_filter("fecha")
def filtro_fecha(valor):
    if not valor:
        return "-"
    return valor.astimezone(fd.BOLIVIA).strftime("%d/%m/%Y %H:%M:%S") + " (hora de Bolivia)"


@app.after_request
def sin_cache(respuesta):
    respuesta.headers["Cache-Control"] = "no-store"
    return respuesta


@app.errorhandler(413)
def demasiado_grande(_e):
    return render_template("error.html", mensaje="El archivo supera el tamaño máximo permitido (60 MB)."), 413


# ---------------------------------------------------------------------------
@app.route("/")
def inicio():
    return render_template("inicio.html", activa="inicio")


@app.route("/generar", methods=["GET", "POST"])
def generar():
    if request.method == "GET":
        return render_template("generar.html", activa="generar", valores={}, error=None, ident=None)
    f = request.form
    valores = {k: f.get(k, "") for k in ("nombre", "organizacion", "pais", "correo", "dias", "bits")}
    if f.get("contrasena", "") != f.get("contrasena2", ""):
        return render_template("generar.html", activa="generar", valores=valores, ident=None,
                               error="Las contraseñas no coinciden."), 400
    try:
        ident = fd.generar_identidad(f.get("nombre"), f.get("organizacion"), f.get("pais"), f.get("correo"),
                                     f.get("dias") or 365, f.get("bits") or 2048, f.get("contrasena"))
    except fd.ErrorFirma as e:
        return render_template("generar.html", activa="generar", valores=valores, ident=None, error=str(e)), 400
    slug = fd.nombre_seguro(ident.nombre)
    publicos = [
        {"nombre": f"publica_{slug}.pem", "etiqueta": "Llave pública (PEM)", "datos": ident.pem_publica},
        {"nombre": f"certificado_{slug}.pem", "etiqueta": "Certificado X.509 (PEM)", "datos": ident.pem_certificado},
    ]
    privados = [
        {"nombre": f"privada_cifrada_{slug}.pem", "etiqueta": "Llave privada cifrada (PEM)", "datos": ident.pem_privada_cifrada},
        {"nombre": f"identidad_{slug}.p12", "etiqueta": "Identidad para firmar (PKCS#12 .p12)", "datos": ident.p12},
    ]
    for a in publicos + privados:
        a["url"] = _data_url(a["datos"], "application/octet-stream")
        a["tam"] = len(a["datos"])
    memoria = io.BytesIO()
    with zipfile.ZipFile(memoria, "w", zipfile.ZIP_DEFLATED) as z:
        for a in publicos:
            z.writestr(a["nombre"], a["datos"])
    zip_publico = {"nombre": f"llaves_publicas_{slug}.zip", "url": _data_url(memoria.getvalue(), "application/zip")}
    return render_template("generar.html", activa="generar", valores=valores, error=None, ident=ident,
                           publicos=publicos, privados=privados, zip_publico=zip_publico)


def _nombre_firmado(original: str) -> str:
    base = re.sub(r"\.pdf$", "", secure_filename(original or "") or "documento", flags=re.I)
    m = re.fullmatch(r"(.*)_firmado(\d*)", base)
    if m:
        return f"{m.group(1)}_firmado{int(m.group(2) or 1) + 1}.pdf"
    return f"{base}_firmado.pdf"


@app.route("/firmar", methods=["GET", "POST"])
def firmar():
    if request.method == "GET":
        return render_template("firmar.html", activa="firmar", error=None, valores={}, res=None)
    f = request.form
    valores = {k: f.get(k, "") for k in ("motivo", "lugar", "pagina")}
    valores["visible"] = f.get("visible") == "on"
    archivo_pdf, archivo_p12 = request.files.get("pdf"), request.files.get("p12")
    if not archivo_pdf or not archivo_pdf.filename or not archivo_p12 or not archivo_p12.filename:
        return render_template("firmar.html", activa="firmar", valores=valores, res=None,
                               error="Selecciona el PDF y tu archivo de identidad (.p12)."), 400
    pagina = None
    if valores["pagina"].strip():
        if not valores["pagina"].strip().isdigit() or int(valores["pagina"]) < 1:
            return render_template("firmar.html", activa="firmar", valores=valores, res=None,
                                   error="El número de página debe ser un entero positivo."), 400
        pagina = int(valores["pagina"])
    try:
        res = fd.firmar_pdf(archivo_pdf.read(), archivo_p12.read(), f.get("contrasena", ""),
                            valores["motivo"], valores["lugar"], valores["visible"], pagina)
    except fd.ErrorFirma as e:
        return render_template("firmar.html", activa="firmar", valores=valores, res=None, error=str(e)), 400
    nombre = _nombre_firmado(archivo_pdf.filename)
    token = _guardar(res.pdf_firmado, nombre, "application/pdf")
    return render_template("firmar.html", activa="firmar", valores=valores, error=None, res=res,
                           token=token, nombre_salida=nombre, tam=len(res.pdf_firmado))


@app.route("/descargar/<token>")
def descargar(token):
    with _CERROJO:
        entrada = _ALMACEN.get(token)
        if not entrada or entrada["vence"] < time.time():
            abort(404)
        datos, nombre, tipo = entrada["datos"], entrada["nombre"], entrada["tipo"]
    return send_file(io.BytesIO(datos), mimetype=tipo, as_attachment=True, download_name=nombre)


@app.route("/validar", methods=["GET", "POST"])
def validar():
    if request.method == "GET":
        return render_template("validar.html", activa="validar", error=None, res=None)
    archivo_pdf = request.files.get("pdf")
    if not archivo_pdf or not archivo_pdf.filename:
        return render_template("validar.html", activa="validar", res=None, error="Selecciona el PDF firmado."), 400
    confianzas = [a.read() for a in request.files.getlist("confianzas") if a and a.filename]
    try:
        res = fd.validar_pdf(archivo_pdf.read(), confianzas)
    except fd.ErrorFirma as e:
        return render_template("validar.html", activa="validar", res=None, error=str(e)), 400
    return render_template("validar.html", activa="validar", error=None, res=res,
                           nombre_pdf=secure_filename(archivo_pdf.filename) or "documento.pdf",
                           num_confianzas=len(confianzas))


if __name__ == "__main__":
    print("\n  Aplicación de firma digital lista.")
    print("  Abre en tu navegador:  http://127.0.0.1:5000\n  (Ctrl+C para detenerla)\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
