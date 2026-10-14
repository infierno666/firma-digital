# -*- coding: utf-8 -*-
"""Utilidades de prueba: genera un PDF mínimo válido sin depender de otras bibliotecas."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def pdf_minimo(paginas: int = 2) -> bytes:
    objetos = {}
    hijos = []
    siguiente = 4                                   # 1 = catálogo, 2 = páginas, 3 = fuente
    for i in range(paginas):
        flujo = f"BT /F1 18 Tf 72 720 Td (Pagina {i + 1} del documento de prueba) Tj ET".encode()
        num_pag, num_cont = siguiente, siguiente + 1
        siguiente += 2
        hijos.append(num_pag)
        objetos[num_pag] = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {num_cont} 0 R "
                            "/Resources << /Font << /F1 3 0 R >> >> >>").encode()
        objetos[num_cont] = b"<< /Length %d >>\nstream\n" % len(flujo) + flujo + b"\nendstream"
    objetos[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objetos[2] = ("<< /Type /Pages /Kids [%s] /Count %d >>" % (" ".join(f"{h} 0 R" for h in hijos), paginas)).encode()
    objetos[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    salida = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for n in sorted(objetos):
        offsets[n] = len(salida)
        salida += b"%d 0 obj\n" % n + objetos[n] + b"\nendobj\n"
    inicio_xref = len(salida)
    total = max(objetos) + 1
    salida += b"xref\n0 %d\n0000000000 65535 f \n" % total
    for n in range(1, total):
        salida += b"%010d 00000 n \n" % offsets[n]
    salida += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (total, inicio_xref)
    return bytes(salida)
