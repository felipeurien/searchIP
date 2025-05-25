import os
import requests
from dotenv import load_dotenv
import ipaddress

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY") # Se carga pero no se usa en esta versión
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")     # Se carga pero no se usa en esta versión

def validateIP(ip_string: str) -> bool:
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def useVirusTotal(ip_address: str, api_key: str) -> dict:
    if not api_key:
        return {"error": "No VirusTotal API KEY provided to function"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 401:
             return {"error": f"Error de autenticación en VirusTotal (HTTP {response.status_code}). Verifica tu API Key."}
        elif response.status_code == 429:
             return {"error": f"Límite de tasa excedido en VirusTotal (HTTP {response.status_code}). Espera un momento."}
        elif response.status_code == 404:
             return {"error": f"IP no encontrada en VirusTotal (HTTP {response.status_code}).", "data": None}
        else:
             return {"error": f"Error HTTP en VirusTotal: {http_err} (Código: {response.status_code})"}
    except requests.exceptions.ConnectionError as conn_err:
        return {"error": f"Error de conexión con VirusTotal: {conn_err}"}
    except requests.exceptions.Timeout as timeout_err:
        return {"error": f"Timeout durante la conexión con VirusTotal: {timeout_err}"}
    except requests.exceptions.RequestException as req_err:
        return {"error": f"Error en la solicitud a VirusTotal: {req_err}"}
    except ValueError:
        return {"error": "Error al decodificar la respuesta JSON de VirusTotal."}

def main():
    ips_input_string = input("Ingresa las direcciones IP separadas por espacios: ")
    ip_list = [ip.strip() for ip in ips_input_string.split() if ip.strip()]

    if not ip_list:
        print("No se ingresaron direcciones IP.")
        return

    malicious_ips_summary_details = []

    for ip_input in ip_list:
        print(f"\n--- Procesando IP: {ip_input} ---")

        if not validateIP(ip_input):
            print(f"'{ip_input}' no es una dirección IP válida.")
            continue

        print(f"[VT] Analizando IP: {ip_input}...")
        responseVT = useVirusTotal(ip_input, VT_API_KEY)
        
        print(f"Resultados para '{ip_input}' desde VirusTotal:")
        if "error" in responseVT:
            print(f"  Error: {responseVT['error']}")
        elif responseVT and "data" in responseVT:
            attributes = responseVT.get("data", {}).get("attributes", {})
            reputation = attributes.get("reputation")
            owner = attributes.get("as_owner")
            country = attributes.get("country")
            stats = attributes.get("last_analysis_stats", {})

            print(f"  Reputación VT: {reputation if reputation is not None else 'N/A'}")
            if owner:
                print(f"  Propietario AS: {owner}")
            else:
                print("  Propietario AS: N/A")
            if country:
                print(f"  País: {country}")
            else:
                print("  País: N/A")

            if stats:
                malicious_count = stats.get('malicious', 0) # Guardar el conteo
                print(f"  Estadísticas del último análisis:")
                print(f"    Inofensivo (harmless): {stats.get('harmless', 0)}")
                print(f"    Malicioso (malicious): {malicious_count}")
                print(f"    Sospechoso (suspicious): {stats.get('suspicious', 0)}")
                print(f"    No detectado (undetected): {stats.get('undetected', 0)}")
                
                if malicious_count > 0:
                    malicious_ips_summary_details.append({'ip': ip_input, 'count': malicious_count})
            else:
                print("  No se encontraron estadísticas de análisis recientes.")
        else:
            print("  No se recibió información estructurada o la IP no fue encontrada en VirusTotal.")
        
    # ---Print details---
    print("\n\n-------------------------------------------")
    print("--- Resumen de IPs Potencialmente Maliciosas (VirusTotal) ---")
    print("-------------------------------------------")

    if malicious_ips_summary_details:
        print("Las siguientes IPs tuvieron al menos 1 detección 'maliciosa':")
        for item in malicious_ips_summary_details:
            plural_s = "s" if item['count'] > 1 else "" 
            print(f"  - {item['ip']}: {item['count']} reporte{plural_s} malicioso{plural_s}")
    else:
        print("Ninguna de las IPs analizadas tuvo detecciones 'maliciosas' según VirusTotal.")
    print("-------------------------------------------")

if __name__ == "__main__":
    if not VT_API_KEY:
        print("Error: Falta la clave API de VirusTotal (VIRUSTOTAL_API_KEY) en el archivo .env o como variable de entorno.")
    else:
        if not all([VT_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY]):
             print("Advertencia: Una o más claves API (ABUSEIPDB_API_KEY, SHODAN_API_KEY) no están configuradas.")
             print("El script continuará solo con las APIs cuyas claves estén presentes y se usen.")
        main()