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
import hashlib
import whois
from datetime import datetime
from bs4 import BeautifulSoup
from colorama import init, Fore
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Desactivar advertencias de certificados SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
init(autoreset=True)

USER_AGENTS =[
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
]

def imprimir_banner():
    banner = pyfiglet.figlet_format("Z-OSINT", font="small")
    console.print(f"[bold magenta]{banner}[/bold magenta]")
    console.print("[bold white] ➔ Advanced Reconnaissance & Threat Intelligence System[/bold white]")
    console.print("[dim cyan]─────────────────────────────────────────────────────────────────[/dim cyan]\n")

def extraer_nombre_empresa_avanzado(dominio):
    proveedores_publicos =['gmail', 'hotmail', 'outlook', 'yahoo', 'icloud', 'protonmail', 'live']
    nombre_base = dominio.split('.')[0].lower()
    if nombre_base in proveedores_publicos: return None
    try:
        url = f"https://{dominio}"
        response = requests.get(url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=5, verify=False)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            titulo = soup.title.string if soup.title else ""
            nombre_limpio = re.split(r'[|-]', titulo)[0].strip()
            if len(nombre_limpio) > 2: return nombre_limpio
    except: pass
    temp = re.sub(r'\.(com|edu|gob|org|net|mil|co|ac)\.(pe|ar|mx|cl|co|es|uk|br)$', '', dominio)
    temp = re.sub(r'\.(com|net|org|edu|pe|io|ai|biz|info|me|tv|us)$', '', temp)
    return temp.split('.')[-1].title()

def analizar_proveedores_correo(spf_str):
    if spf_str == "No encontrado": return "[dim]Sin registro SPF[/dim]"
    proveedores =[]
    spf_l = spf_str.lower()
    if 'google' in spf_l: proveedores.append("Google Workspace")
    if 'outlook' in spf_l or 'spf.protection' in spf_l: proveedores.append("Microsoft 365")
    if 'sendgrid' in spf_l: proveedores.append("SendGrid (Mailing)")
    if 'mandrill' in spf_l: proveedores.append("Mandrill (Mailing)")
    if 'mcsv' in spf_l or 'mcdlv' in spf_l: proveedores.append("Mailchimp")
    if 'zoho' in spf_l: proveedores.append("Zoho Mail")
    if 'amazon' in spf_l or 'ses' in spf_l: proveedores.append("AWS SES")
    return ", ".join(proveedores) if proveedores else "Servidores Propios/IPs"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        org = w.org or w.organization
        exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        return {
            "registrar": w.registrar or "Desconocido",
            "expiracion": exp.strftime('%Y-%m-%d') if exp else "Desconocido",
            "organizacion": org if org else "No declarada"
        }
    except: return {"registrar": "Error", "expiracion": "Error", "organizacion": "Error"}

def check_dns_security(domain):
    res = {"spf": "No encontrado", "dmarc": "No encontrado", "vulnerable": "Sí (Crítico)"}
    try:
        spf_rec = dns.resolver.resolve(domain, 'TXT')
        for txt in spf_rec:
            t_str = "".join([t.decode() if isinstance(t, bytes) else str(t) for t in txt.strings])
            if 'v=spf1' in t_str: res["spf"] = t_str; break
        dmarc_rec = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for txt in dmarc_rec:
            t_str = "".join([t.decode() if isinstance(t, bytes) else str(t) for t in txt.strings])
            if 'v=DMARC1' in t_str:
                res["dmarc"] = t_str
                res["vulnerable"] = "No" if ("p=reject" in t_str.lower() or "p=quarantine" in t_str.lower()) else "Parcial (p=none)"
                break
    except: pass
    return res

def check_gravatar(email):
    hash_md5 = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    try:
        url = f"https://en.gravatar.com/{hash_md5}.json"
        req = requests.get(url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=5)
        if req.status_code == 200:
            data = req.json()['entry'][0]
            name = data.get('displayName', data.get('name', {}).get('formatted', ''))
            return f"✅ Encontrado | Nombre: {name}"
    except: pass
    return "❌ No registrado"

def check_pgp(email):
    try:
        url = f"https://keyserver.ubuntu.com/pks/lookup?search={email}&op=index"
        req = requests.get(url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=5)
        if "pub  " in req.text: return "✅ Llave Criptográfica PGP encontrada"
    except: pass
    return "❌ Sin llaves públicas"

def get_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = requests.get(url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=10)
        if req.status_code == 200:
            subs = {sub.strip().lower() for item in req.json() for sub in item['name_value'].split('\n')}
            return len(subs), list(subs)[:3]
    except: pass
    return 0,[]

def buscar_con_holehe(email):
    path_holehe = shutil.which('holehe')
    comando = [path_holehe, '--only-used', email] if path_holehe else ['python3', '-m', 'holehe', '--only-used', email]
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, encoding='utf-8', timeout=30)
        blacklist = ["Email used", "Rate limit", "Email not used", "is used"]
        return [l.replace('[+]', '').strip() for l in resultado.stdout.splitlines() if '[+]' in l and not any(w in l for w in blacklist)]
    except: return[]

def procesar_objetivo(email):
    console.print(f"\n[bold yellow][*][/bold yellow] Analizando Objetivo:[bold white]{email}[/bold white]\n")
    dominio = email.split('@')[-1]
    empresa_real = extraer_nombre_empresa_avanzado(dominio)
    prefijo = email.split('@')[0]
    nombre_estimado = prefijo.title()
    
    query_empresa = f'"{empresa_real}"' if empresa_real else ""
    dork_linkedin = f'https://www.google.com/search?q=site:linkedin.com/in/+"{nombre_estimado}"+{query_empresa}'.replace(" ", "+")

    with ThreadPoolExecutor(max_workers=10) as executor:
        f_holehe = executor.submit(buscar_con_holehe, email)
        f_leaks = executor.submit(lambda: requests.get(f"https://leakcheck.net/api/public?check={email}").json())
        f_dns = executor.submit(check_dns_security, dominio)
        f_whois = executor.submit(get_whois_info, dominio)
        f_rock = executor.submit(lambda: requests.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}").json())
        f_gravatar = executor.submit(check_gravatar, email)
        f_pgp = executor.submit(check_pgp, email)
        f_crtsh = executor.submit(get_subdomains, dominio)

    redes = f_holehe.result()
    leaks = f_leaks.result().get('sources',[]) if f_leaks.result().get('success') else[]
    dns_sec = f_dns.result()
    whois_data = f_whois.result()
    malware = f_rock.result().get('stealers',[])
    gravatar_data = f_gravatar.result()
    pgp_data = f_pgp.result()
    total_subs, subs_ejemplo = f_crtsh.result()

    org_whois = str(whois_data['organizacion']).lower()
    if any(p in org_whois for p in ['redacted', 'privacy', 'gdpr', 'protected']) or org_whois == "error":
        org_display = empresa_real
    else: org_display = whois_data['organizacion']

    # ==========================
    # UI RENDERIZADO MEJORADO
    # ==========================

    # 1. PERFIL DE IDENTIDAD
    t1 = Table(show_header=False, box=None, padding=(0, 2))
    t1.add_row("🏢 [bold cyan]Organización:[/bold cyan]", f"[bold white]{org_display}[/bold white]")
    t1.add_row("👤 [bold cyan]Alias/Usuario:[/bold cyan]", f"{nombre_estimado}")
    t1.add_row("🔍[bold cyan]LinkedIn Dork:[/bold cyan]", f"[blue underline]{dork_linkedin}[/blue underline]")
    console.print(Panel(t1, title="[bold magenta]1. Inteligencia de Identidad[/bold magenta]", border_style="magenta"))

    # 2. HUELLA DIGITAL
    t2 = Table(show_header=False, box=None, padding=(0, 2))
    t2.add_row("🌐 [bold cyan]Cuentas Activas:[/bold cyan]", ", ".join(redes) if redes else "[dim]Ninguna detectada[/dim]")
    t2.add_row("🖼️ [bold cyan]Perfil Gravatar:[/bold cyan]", gravatar_data)
    t2.add_row("🔑 [bold cyan]Llaves PGP:[/bold cyan]", pgp_data)
    console.print(Panel(t2, title="[bold blue]2. Huella Digital (Footprint)[/bold blue]", border_style="blue"))

    # 3. INFRAESTRUCTURA Y DOMINIO
    t3 = Table(show_header=False, box=None, padding=(0, 2))
    t3.add_row("📌 [bold cyan]Registrar:[/bold cyan]", f"{whois_data['registrar']} (Expira: {whois_data['expiracion']})")
    subs_txt = f"{total_subs} subdominios detectados (ej. {', '.join(subs_ejemplo)})" if total_subs > 0 else "[dim]Búsqueda crt.sh vacía/timeout[/dim]"
    t3.add_row("🕸️ [bold cyan]Infraestructura:[/bold cyan]", subs_txt)
    
    # Análisis de Correos amigable
    stack_correo = analizar_proveedores_correo(dns_sec['spf'])
    t3.add_row("\n📧 [bold cyan]Stack Tecnológico de Correo:[/bold cyan]")
    t3.add_row("", f"↳ Utilizan:[bold yellow]{stack_correo}[/bold yellow]")
    t3.add_row("", f"↳ [dim]SPF Crudo: {dns_sec['spf'][:75]}...[/dim]")

    # Análisis de Riesgo DMARC
    estado_dmarc = "[bold red]🚨 Alta (Sin protección o p=none) - Permite suplantación de identidad[/bold red]" if "Sí" in dns_sec['vulnerable'] or "Parcial" in dns_sec['vulnerable'] else "[bold green]✅ Segura (Bloquea Spoofing)[/bold green]"
    t3.add_row("\n🛡️ [bold cyan]Vulnerabilidad a Spoofing (DMARC):[/bold cyan]")
    t3.add_row("", estado_dmarc)
    
    console.print(Panel(t3, title="[bold yellow]3. Auditoría de Infraestructura y Riesgo[/bold yellow]", border_style="yellow"))

    # 4. INTELIGENCIA DE AMENAZAS (THREAT INTEL)
    t4 = Table(show_header=False, box=None, padding=(0, 2))
    
    if leaks:
        leaks_txt = f"[bold red]❌ {len(leaks)} bases de datos hackeadas[/bold red] (ej. {leaks[0]['name']}, {leaks[1]['name'] if len(leaks)>1 else ''})"
    else:
        leaks_txt = "[bold green]✅ Correo limpio (Sin contraseñas filtradas)[/bold green]"
        
    if malware:
        malware_txt = f"[bold red]🚨 ALERTA CRÍTICA: {len(malware)} registros en Redes de Bots (Stealers)[/bold red]"
    else:
        malware_txt = "[bold green]✅ Sin infecciones de malware detectadas[/bold green]"

    t4.add_row("🔓 [bold cyan]Filtraciones (Breaches):[/bold cyan]", leaks_txt)
    t4.add_row("🦠 [bold cyan]Malware (Infostealers):[/bold cyan]", malware_txt)
    console.print(Panel(t4, title="[bold red]4. Exposición a Amenazas (Threat Intel)[/bold red]", border_style="red"))

    # GUARDADO
    reporte = {
        "email": email, "fecha": str(datetime.now()),
        "identidad": {"alias": nombre_estimado, "organizacion": org_display, "gravatar": gravatar_data},
        "infraestructura": {"registrar": whois_data['registrar'], "stack_correo": stack_correo, "riesgo_spoofing": estado_dmarc.replace('[bold red]', '').replace('[/bold red]', '')},
        "amenazas": {"leaks_count": len(leaks), "malware_count": len(malware)}
    }
    filename = f"report_{email.replace('@','_')}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(reporte, f, indent=4, ensure_ascii=False)
    console.print(f" [bold white on green] ÉXITO [/bold white on green] Datos guardados en: [bold]{filename}[/bold]\n")

def main():
    imprimir_banner()
    if len(sys.argv) > 1:
        procesar_objetivo(sys.argv[1])
    else:
        try:
            email = input(Fore.WHITE + "[" + Fore.MAGENTA + "?" + Fore.WHITE + "] Email Objetivo: ").strip()
            if email: procesar_objetivo(email)
        except EOFError: return

if __name__ == '__main__':
    main()
