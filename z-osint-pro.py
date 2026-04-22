#!/usr/bin/env python3
import pyfiglet
import subprocess
import requests
import shutil
import json
import re
import sys
import dns.resolver
import random
import os
import hashlib
import whois
import time
from datetime import datetime
from bs4 import BeautifulSoup
from colorama import init, Fore
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Inicialización
init(autoreset=True)
console = Console()

def imprimir_banner():
    banner = pyfiglet.figlet_format("Z-OSINT PRO", font="small")
    console.print(f"[bold magenta]{banner}[/bold magenta]")
    console.print("[bold green] v5.1 - Corporate Recon Edition[/bold green]")
    console.print("[cyan]─────────────────────────────────────────────────────────────────[/cyan]\n")

def extraer_nombre_empresa_avanzado(dominio):
    """
    Intenta obtener el nombre real de la empresa mediante:
    1. Scraping del título de su página web (más preciso).
    2. Análisis inteligente del dominio (fallback).
    """
    # 1. Detectar proveedores de correo personal
    proveedores_publicos = ['gmail', 'hotmail', 'outlook', 'yahoo', 'icloud', 'protonmail', 'live']
    nombre_base = dominio.split('.')[0].lower()
    if nombre_base in proveedores_publicos:
        return None

    # 2. Intentar Scraping del Título Web (OSINT Real)
    try:
        url = f"https://{dominio}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            titulo = soup.title.string if soup.title else ""
            # Limpiar el título (ej: "Tecsup - Pasión por la tecnología" -> "Tecsup")
            nombre_limpio = re.split(r'[|-]', titulo)[0].strip()
            if len(nombre_limpio) > 2:
                return nombre_limpio
    except:
        pass

    # 3. Fallback: Lógica de limpieza de dominio avanzada
    # Eliminar extensiones compuestas (edu.pe, com.mx, etc.)
    temp = re.sub(r'\.(com|edu|gob|org|net|mil|co|ac)\.(pe|ar|mx|cl|co|es|uk|br)$', '', dominio)
    # Eliminar extensiones simples
    temp = re.sub(r'\.(com|net|org|edu|pe|io|ai|biz|info|me|tv|us)$', '', temp)
    # Si queda algo como 'sub.empresa', tomar 'empresa'
    resultado = temp.split('.')[-1].capitalize()
    return resultado

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        # Intentar obtener la organización oficial del registro Whois
        org = w.org or w.organization
        exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        return {
            "registrar": w.registrar or "N/A",
            "expiracion": exp.strftime('%Y-%m-%d') if exp else "N/A",
            "organizacion": org if org else "No declarada"
        }
    except: return {"registrar": "Error", "expiracion": "Error", "organizacion": "Error"}

def check_dns_security(domain):
    res = {"spf": "No encontrado", "dmarc": "No encontrado", "vulnerable": "Sí (Crítico)"}
    try:
        spf_rec = dns.resolver.resolve(domain, 'TXT')
        for txt in spf_rec:
            txt_str = "".join([t.decode() if isinstance(t, bytes) else str(t) for t in txt.strings])
            if 'v=spf1' in txt_str:
                res["spf"] = txt_str
                break
        dmarc_rec = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for txt in dmarc_rec:
            txt_str = "".join([t.decode() if isinstance(t, bytes) else str(t) for t in txt.strings])
            if 'v=DMARC1' in txt_str:
                res["dmarc"] = txt_str
                res["vulnerable"] = "No" if ("p=reject" in txt_str.lower() or "p=quarantine" in txt_str.lower()) else "Parcial (p=none)"
                break
    except: pass
    return res

def buscar_con_holehe(email):
    path_holehe = shutil.which('holehe')
    comando = [path_holehe, '--only-used', email] if path_holehe else ['python3', '-m', 'holehe', '--only-used', email]
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, encoding='utf-8', timeout=40)
        blacklist = ["Email used", "Rate limit", "Email not used", "is used"]
        return [l.replace('[+]', '').strip() for l in resultado.stdout.splitlines() if '[+]' in l and not any(w in l for w in blacklist)]
    except: return []

def procesar_objetivo(email):
    console.print(f"\n[bold yellow][*][/bold yellow] Analizando objetivo: [bold cyan]{email}[/bold cyan]...")
    dominio = email.split('@')[-1]

    # --- RECONOCIMIENTO CORPORATIVO AVANZADO ---
    empresa_real = extraer_nombre_empresa_avanzado(dominio)
    prefijo = email.split('@')[0]
    nombre_estimado = re.sub(r'[._-]', ' ', prefijo).title()
    nombre_estimado = ''.join([i for i in nombre_estimado if not i.isdigit()]).strip()

    # LinkedIn Smart Dork con Nombre + Empresa Real
    query_empresa = f'"{empresa_real}"' if empresa_real else ""
    query_linkedin = f'https://www.google.com/search?q=site:linkedin.com/in/+"{nombre_estimado.replace(" ","+")}"+{query_empresa}'

    with ThreadPoolExecutor(max_workers=7) as executor:
        f_holehe = executor.submit(buscar_con_holehe, email)
        f_leaks = executor.submit(lambda: requests.get(f"https://leakcheck.net/api/public?check={email}").json())
        f_dns = executor.submit(check_dns_security, dominio)
        f_whois = executor.submit(get_whois_info, dominio)
        f_rock = executor.submit(lambda: requests.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}").json())

    # --- RECOLECCIÓN ---
    redes = f_holehe.result()
    leaks_data = f_leaks.result()
    leaks = leaks_data.get('sources', []) if leaks_data.get('success') else []
    dns_sec = f_dns.result()
    whois_data = f_whois.result()
    malware = f_rock.result().get('stealers', [])

    # --- CORRECCIÓN: FILTRADO DE DATA REDACTED ---
    org_whois = str(whois_data['organizacion'])
    palabras_basura = ['redacted', 'privacy', 'masking', 'gdpr', 'whoisguard', 'protected', 'statutory', 'no declarada']
    
    # Si el whois contiene basura de privacidad o es un Error, usamos el nombre extraído de la web
    if any(p in org_whois.lower() for p in palabras_basura) or whois_data['organizacion'] == "Error":
        org_display = empresa_real
    else:
        org_display = whois_data['organizacion']

    # --- RENDERIZADO ---
    identidad_table = Table(show_header=False, box=None)
    identidad_table.add_row("[bold cyan]Nombre Estimado:[/bold cyan]", f"[bold white]{nombre_estimado}[/bold white]")
    identidad_table.add_row("[bold cyan]Organización:[/bold cyan]", f"[bold yellow]{org_display}[/bold yellow]")
    identidad_table.add_row("[bold cyan]LinkedIn (Smart):[/bold cyan]", f"[blue]{query_linkedin}[/blue]")
    console.print(Panel(identidad_table, title="[bold magenta]👤 Inteligencia de Identidad[/bold magenta]", border_style="magenta"))

    dns_table = Table(show_header=True, header_style="bold yellow", box=None, expand=True)
    dns_table.add_column("Servicio")
    dns_table.add_column("Detalle")
    dns_table.add_row("Registrar", whois_data['registrar'])
    dns_table.add_row("Expiración", whois_data['expiracion'])
    dns_table.add_row("SPF Record", f"[white]{dns_sec['spf']}[/white]")
    dns_table.add_row("DMARC Record", f"[white]{dns_sec['dmarc']}[/white]")
    vuln_style = "bold red" if "Sí" in dns_sec['vulnerable'] else "bold green"
    dns_table.add_row("Vulnerable Spoofing", f"[{vuln_style}]{dns_sec['vulnerable']}[/{vuln_style}]")
    console.print(Panel(dns_table, title="[bold yellow]🛡️ Seguridad Corporativa[/bold yellow]", border_style="yellow"))

    web_table = Table(show_header=True, header_style="bold green", box=None, expand=True)
    web_table.add_column("Categoría")
    web_table.add_column("Hallazgos")
    web_table.add_row("Cuentas Activas", ", ".join(redes) if redes else "[dim]No detectadas[/dim]")
    leak_list = ", ".join([f"{s['name']} ({s['date']})" for s in leaks]) if leaks else "Ninguna"
    web_table.add_row("Breaches (Leaks)", f"[bold red]{leak_list}[/bold red]" if leaks else "[green]Limpio[/green]")
    malware_info = f"[bold red]ALERTA: {len(malware)} infecciones[/bold red]" if malware else "[green]Sin registros[/green]"
    web_table.add_row("Infostealer Malware", malware_info)
    console.print(Panel(web_table, title="[bold green]🌐 Redes & Breaches[/bold green]", border_style="green"))

    # GUARDADO
    reporte = {
        "email": email, "timestamp": str(datetime.now()), "organizacion": org_display,
        "dns": dns_sec, "whois": whois_data, "social": redes, "leaks": leaks
    }
    filename = f"report_{email.replace('@','_')}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(reporte, f, indent=4, ensure_ascii=False)
    console.print(f"\n[bold white on green] ÉXITO [/bold white on green] Reporte generado: [bold]{filename}[/bold]\n")

def main():
    imprimir_banner()
    if len(sys.argv) > 1:
        target = sys.argv[1]
        procesar_objetivo(target)
    else:
        try:
            email = input(Fore.CYAN + "Ingresa el correo: ").strip()
            if email: procesar_objetivo(email)
        except EOFError: return

if __name__ == '__main__':
    # Ignorar advertencias de SSL al hacer scraping web
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
