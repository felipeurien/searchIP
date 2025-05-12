import os
import requests
from dotenv import load_dotenv
import ipaddress

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

def validateIP(ip_string):
    try:
        ipaddress.ip_address(ip_string)
        return True  
    except ValueError:
        return False

def useVirusTotal(ip_address: str, api_key: str) -> dict:
    if not api_key:
        return {"error": "No VirusTotal API KEY"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    print(f"[VT] Analizing IP: {ip_address}...")

    try:
        response = requests.get(url, headers=headers, timeout=10) # 10 second timeout
        response.raise_for_status() 

        return response.json() 

    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 401: # Unauthorized
             return {"error": f"Error de autenticación en VirusTotal (HTTP {response.status_code}). Verifica tu API Key."}
        elif response.status_code == 429: # Too Many Requests
             return {"error": f"Límite de tasa excedido en VirusTotal (HTTP {response.status_code}). Espera un momento."}
        elif response.status_code == 404: # Not Found
             return {"error": f"IP no encontrada en VirusTotal (HTTP {response.status_code}).", "data": None} # Puedes decidir devolver None o una estructura específica
        else:
             return {"error": f"Error HTTP en VirusTotal: {http_err} (Código: {response.status_code})"}
    except requests.exceptions.ConnectionError as conn_err:
        return {"error": f"Error de conexión con VirusTotal: {conn_err}"}
    except requests.exceptions.Timeout as timeout_err:
        return {"error": f"Timeout durante la conexión con VirusTotal: {timeout_err}"}
    except requests.exceptions.RequestException as req_err:
        return {"error": f"Error en la solicitud a VirusTotal: {req_err}"}
    except ValueError: # Si response.json() falla
        return {"error": "Error al decodificar la respuesta JSON de VirusTotal."}

def main():
    ipInput = input("Enter IP: ")

    if not validateIP(ipInput):
        print("IP is not valid")
        return

    responseVT = useVirusTotal(ipInput, VT_API_KEY)

    if "error" in responseVT:
        print(f"Error from VT: {responseVT['error']}")
    elif responseVT and "data" in responseVT:
        attributes = responseVT.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation")
        owner = attributes.get("as_owner")
        country = attributes.get("country") 
    print(f"  Reputación VT: {reputation}")
    if owner:
        print(f"  Propietario AS: {owner}")
    if country:
        print(f"  País: {country}")

    if stats:
        print(f"  Estadísticas del último análisis:")
        print(f"    Inofensivo (harmless): {stats.get('harmless', 0)}")
        print(f"    Malicioso (malicious): {stats.get('malicious', 0)}")
        print(f"    Sospechoso (suspicious): {stats.get('suspicious', 0)}")
        print(f"    No detectado (undetected): {stats.get('undetected', 0)}")
    else:
        print("  No se encontraron estadísticas de análisis recientes.")


if __name__ == "__main__":
    if not all([VT_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY]):
        print("Error: API key missing.")
    else:
        main()