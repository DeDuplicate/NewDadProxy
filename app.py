from flask import Flask, request, Response
import requests
from urllib.parse import urlparse, urljoin, quote, unquote
import re
import traceback
import os
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

app = Flask(__name__)

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def detect_m3u_type(content):
    """Rileva se è un M3U (lista IPTV) o un M3U8 (flusso HLS)"""
    if "#EXTM3U" in content and "#EXTINF" in content:
        return "m3u8"
    return "m3u"

def replace_key_uri(line, headers_query):
    """Sostituisce l'URI della chiave AES-128 con il proxy"""
    match = re.search(r'URI="([^"]+)"', line)
    if match:
        key_url = match.group(1)
        proxied_key_url = f"/proxy/key?url={quote(key_url)}&{headers_query}"
        return line.replace(key_url, proxied_key_url)
    return line

def resolve_m3u8_link(url, headers=None):
    """
    Tenta di risolvere un URL M3U8.
    Prova prima la logica specifica per iframe (tipo Daddylive), inclusa la lookup della server_key.
    Se fallisce, verifica se l'URL iniziale era un M3U8 diretto e lo restituisce.
    Supporta anche URL diretti di VidEmbed.
    """
    if not url:
        logger.error("Errore: URL non fornito.")
        return {"resolved_url": None, "headers": {}}

    logger.info(f"Tentativo di risoluzione URL: {url}")
    # Utilizza gli header forniti, altrimenti usa un User-Agent di default
    current_headers = headers if headers else {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0+Safari/537.36'}

    initial_response_text = None
    final_url_after_redirects = None

    # Verifica se è un URL di daddylive/thedaddy
    is_daddylive = any(domain in url.lower() for domain in ["thedaddy.dad", "thedaddy.click", "daddylive.sx"])
    
    # Verifica se è un URL diretto di VidEmbed/CDN
    is_vidembed_cdn = any(domain in url.lower() for domain in [
        "chinese-restaurant-api.site",
        "vidembed.re",
        "vidembed.to",
        "vidembed.cc",
        "vidembed.me",
        ".m3u8"
    ])

    try:
        with requests.Session() as session:
            logger.info(f"Passo 1: Richiesta a {url}")
            
            # Se è daddylive.sx, gestisci il redirect
            if "daddylive.sx" in url.lower():
                # daddylive.sx reindirizza a thedaddy.dad, quindi sostituisci direttamente
                url = url.replace("daddylive.sx", "thedaddy.dad")
                logger.info(f"Convertito daddylive.sx in thedaddy.dad: {url}")
            
            response = session.get(url, headers=current_headers, allow_redirects=True, timeout=(5, 15))
            response.raise_for_status()
            initial_response_text = response.text
            final_url_after_redirects = response.url
            logger.info(f"Passo 1 completato. URL finale dopo redirect: {final_url_after_redirects}")

            # Se è un URL diretto di VidEmbed CDN, restituiscilo direttamente
            if is_vidembed_cdn:
                logger.info(f"Rilevato URL diretto VidEmbed/CDN: {url}")
                # Se è già un M3U8, usa header specifici per VidEmbed
                if ".m3u8" in url.lower():
                    vidembed_headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
                        'Referer': 'https://www.vidembed.re/',
                        'Origin': 'https://www.vidembed.re',
                        'Accept': '*/*',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Accept-Encoding': 'gzip, deflate, br',
                        'Cache-Control': 'no-cache',
                        'Pragma': 'no-cache',
                        'Sec-Fetch-Dest': 'empty',
                        'Sec-Fetch-Mode': 'cors',
                        'Sec-Fetch-Site': 'cross-site'
                    }
                    return {
                        "resolved_url": url,
                        "headers": vidembed_headers
                    }
                # Se è un dominio VidEmbed ma non M3U8, verifica il contenuto
                elif initial_response_text and initial_response_text.strip().startswith('#EXTM3U'):
                    return {
                        "resolved_url": final_url_after_redirects,
                        "headers": current_headers
                    }

            # Se è un URL di daddylive, verifica se è già un M3U8
            if is_daddylive:
                if initial_response_text and initial_response_text.strip().startswith('#EXTM3U'):
                    return {
                        "resolved_url": final_url_after_redirects,
                        "headers": current_headers
                    }
                # Altrimenti continua con la logica dell'iframe per daddylive
                logger.info(f"URL daddylive non è un M3U8 diretto, tentativo con logica iframe: {url}")

            # Prova la logica dell'iframe per gli altri URL
            logger.info("Tentativo con logica iframe...")
            try:
                # Secondo passo (Iframe): Trova l'iframe src nella risposta iniziale
                iframes = re.findall(r'iframe src="([^"]+)"', initial_response_text)
                if not iframes:
                    raise ValueError("Nessun iframe src trovato.")

                url2 = iframes[0]
                logger.info(f"Passo 2 (Iframe): Trovato iframe URL: {url2}")

                # Terzo passo (Iframe): Richiesta all'URL dell'iframe
                referer_raw = urlparse(url2).scheme + "://" + urlparse(url2).netloc + "/"
                origin_raw = urlparse(url2).scheme + "://" + urlparse(url2).netloc
                current_headers['Referer'] = referer_raw
                current_headers['Origin'] = origin_raw
                logger.info(f"Passo 3 (Iframe): Richiesta a {url2}")
                response = session.get(url2, headers=current_headers, timeout=(5, 15), verify=False)
                response.raise_for_status()
                iframe_response_text = response.text
                logger.info("Passo 3 (Iframe) completato.")

                # Quarto passo (Iframe): Estrai parametri dinamici dall'iframe response
                channel_key_match = re.search(r'(?s) channelKey = \"([^\"]*)"', iframe_response_text)
                auth_ts_match = re.search(r'(?s) authTs\s*= \"([^\"]*)"', iframe_response_text)
                auth_rnd_match = re.search(r'(?s) authRnd\s*= \"([^\"]*)"', iframe_response_text)
                auth_sig_match = re.search(r'(?s) authSig\s*= \"([^\"]*)"', iframe_response_text)
                auth_host_match = re.search(r'\}\s*fetchWithRetry\(\s*\'([^\']*)\'', iframe_response_text)
                server_lookup_match = re.search(r'n fetchWithRetry\(\s*\'([^\']*)\'', iframe_response_text)

                if not all([channel_key_match, auth_ts_match, auth_rnd_match, auth_sig_match, auth_host_match, server_lookup_match]):
                    raise ValueError("Impossibile estrarre tutti i parametri dinamici dall'iframe response.")
                
                channel_key = channel_key_match.group(1)
                auth_ts = auth_ts_match.group(1)
                auth_rnd = auth_rnd_match.group(1)
                auth_sig = quote(auth_sig_match.group(1))
                auth_host = auth_host_match.group(1)
                server_lookup = server_lookup_match.group(1)

                logger.info("Passo 4 (Iframe): Parametri dinamici estratti.")

                # Quinto passo (Iframe): Richiesta di autenticazione
                auth_url = f'{auth_host}{channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
                logger.info(f"Passo 5 (Iframe): Richiesta di autenticazione a {auth_url}")
                auth_response = session.get(auth_url, headers=current_headers, timeout=(5, 15), verify=False)
                auth_response.raise_for_status()
                logger.info("Passo 5 (Iframe) completato.")

                # Sesto passo (Iframe): Richiesta di server lookup per ottenere la server_key
                server_lookup_url = f"https://{urlparse(url2).netloc}{server_lookup}{channel_key}"
                logger.info(f"Passo 6 (Iframe): Richiesta server lookup a {server_lookup_url}")
                server_lookup_response = session.get(server_lookup_url, headers=current_headers, timeout=(5, 15), verify=False)
                server_lookup_response.raise_for_status()
                server_lookup_data = server_lookup_response.json()
                logger.info("Passo 6 (Iframe) completato.")

                # Settimo passo (Iframe): Estrai server_key dalla risposta di server lookup
                server_key = server_lookup_data.get('server_key')
                if not server_key:
                    raise ValueError("'server_key' non trovato nella risposta di server lookup.")
                logger.info(f"Passo 7 (Iframe): Estratto server_key: {server_key}")

                # Ottavo passo (Iframe): Costruisci il link finale
                host_match = re.search('(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)"', iframe_response_text)
                if not host_match:
                    raise ValueError("Impossibile trovare l'host finale per l'm3u8.")
                host = host_match.group(1)
                logger.info(f"Passo 8 (Iframe): Trovato host finale per m3u8: {host}")

                # Costruisci l'URL finale del flusso
                final_stream_url = (
                    f'https://{server_key}{host}{server_key}/{channel_key}/mono.m3u8'
                )

                # Prepara gli header per lo streaming
                stream_headers = {
                    'User-Agent': current_headers.get('User-Agent', ''),
                    'Referer': referer_raw,
                    'Origin': origin_raw
                }
                
                return {
                    "resolved_url": final_stream_url,
                    "headers": stream_headers
                }

            except (ValueError, requests.exceptions.RequestException) as e:
                logger.info(f"Logica iframe fallita: {e}")
                logger.info("Tentativo fallback: verifica se l'URL iniziale era un M3U8 diretto...")

                # Fallback: Verifica se la risposta iniziale era un file M3U8 diretto
                if initial_response_text and initial_response_text.strip().startswith('#EXTM3U'):
                    logger.info("Fallback riuscito: Trovato file M3U8 diretto.")
                    return {
                        "resolved_url": final_url_after_redirects,
                        "headers": current_headers
                    }
                else:
                    logger.info("Fallback fallito: La risposta iniziale non era un M3U8 diretto.")
                    return {
                        "resolved_url": url,
                        "headers": current_headers
                    }

    except requests.exceptions.RequestException as e:
        logger.info(f"Errore durante la richiesta HTTP iniziale: {e}")
        return {"resolved_url": url, "headers": current_headers}
    except Exception as e:
        logger.info(f"Errore generico durante la risoluzione: {e}")
        return {"resolved_url": url, "headers": current_headers}

@app.route('/proxy')
def proxy():
    """Proxy per liste M3U che aggiunge automaticamente /m3u?url= con IP prima dei link"""
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    try:
        # Ottieni l'IP del server
        server_ip = request.host
        
        # Scarica la lista M3U originale
        response = requests.get(m3u_url, timeout=(10, 30)) # Timeout connessione 10s, lettura 30s
        response.raise_for_status()
        m3u_content = response.text
        
        # Modifica solo le righe che contengono URL (non iniziano con #)
        modified_lines = []
        for line in m3u_content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                # Per tutti i link, usa il proxy normale
                modified_line = f"http://{server_ip}/m3u?url={line}"
                modified_lines.append(modified_line)
            else:
                # Mantieni invariate le righe di metadati
                modified_lines.append(line)
        
        modified_content = '\n'.join(modified_lines)

        # Estrai il nome del file dall'URL originale
        parsed_m3u_url = urlparse(m3u_url)
        original_filename = os.path.basename(parsed_m3u_url.path)
        
        return Response(modified_content, content_type="application/vnd.apple.mpegurl", headers={'Content-Disposition': f'attachment; filename="{original_filename}"'})
        
    except requests.RequestException as e:
        return f"Errore durante il download della lista M3U: {str(e)}", 500
    except Exception as e:
        return f"Errore generico: {str(e)}", 500

@app.route('/proxy/m3u')
def proxy_m3u():
    """Proxy per file M3U e M3U8 con supporto per redirezioni e header personalizzati"""
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    default_headers = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/33.0 Mobile/15E148 Safari/605.1.15",
        "Referer": "https://forcedtoplay.xyz/",
        "Origin": "https://forcedtoplay.xyz"
    }

    # Estrai gli header dalla richiesta, sovrascrivendo i default
    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }
    headers = {**default_headers, **request_headers}

    # --- Logica per trasformare l'URL se necessario ---
    processed_url = m3u_url
    
    # Se è già un URL diretto M3U8 di VidEmbed/CDN, usalo direttamente
    is_direct_m3u8 = any(domain in m3u_url.lower() for domain in [
        "chinese-restaurant-api.site",
        "vidembed.re",
        "vidembed.to",
        "vidembed.cc",
        "vidembed.me"
    ]) and ".m3u8" in m3u_url.lower()
    
    if is_direct_m3u8:
        logger.info(f"Rilevato URL M3U8 diretto VidEmbed: {m3u_url}")
        # Non necessita trasformazione, verrà gestito da resolve_m3u8_link
    # Trasforma /stream/ in /embed/ per Daddylive
    elif '/stream/stream-' in m3u_url and any(domain in m3u_url for domain in ['thedaddy.dad', 'thedaddy.click', 'daddylive.sx']):
        processed_url = m3u_url.replace('/stream/stream-', '/embed/stream-')
        logger.info(f"URL {m3u_url} trasformato da /stream/ a /embed/: {processed_url}")
    match_premium_m3u8 = re.search(r'/premium(\d+)/mono\.m3u8$', m3u_url)

    if match_premium_m3u8:
        channel_number = match_premium_m3u8.group(1)
        # Usa il dominio dall'URL originale se presente, altrimenti usa thedaddy.dad
        if 'thedaddy.click' in m3u_url:
            transformed_url = f"https://thedaddy.click/embed/stream-{channel_number}.php"
        elif 'daddylive.sx' in m3u_url:
            transformed_url = f"https://daddylive.sx/embed/stream-{channel_number}.php"
        else:
            transformed_url = f"https://thedaddy.dad/embed/stream-{channel_number}.php"
        logger.info(f"URL {m3u_url} corrisponde al pattern premium. Trasformato in: {transformed_url}")
        processed_url = transformed_url
    else:
        logger.info(f"URL {processed_url} processato per la risoluzione.")

    try:
        logger.info(f"Chiamata a resolve_m3u8_link per URL processato: {processed_url}")
        result = resolve_m3u8_link(processed_url, headers)

        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL in un M3U8 valido.", 500

        resolved_url = result["resolved_url"]
        current_headers_for_proxy = result["headers"]

        logger.info(f"Risoluzione completata. URL M3U8 finale: {resolved_url}")

        # Fetchare il contenuto M3U8 effettivo dall'URL risolto
        logger.info(f"Fetching M3U8 content from resolved URL: {resolved_url}")
        m3u_response = requests.get(resolved_url, headers=current_headers_for_proxy, allow_redirects=True, timeout=(10, 20)) # Timeout connessione 10s, lettura 20s
        m3u_response.raise_for_status()
        m3u_content = m3u_response.text
        final_url = m3u_response.url

        # Processa il contenuto M3U8
        file_type = detect_m3u_type(m3u_content)

        if file_type == "m3u":
            return Response(m3u_content, content_type="application/vnd.apple.mpegurl")

        # Processa contenuto M3U8
        parsed_url = urlparse(final_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rsplit('/', 1)[0]}/"

        # Prepara la query degli header per segmenti/chiavi proxati
        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in current_headers_for_proxy.items()])

        modified_m3u8 = []
        for line in m3u_content.splitlines():
            line = line.strip()
            if line.startswith("#EXT-X-KEY") and 'URI="' in line:
                line = replace_key_uri(line, headers_query)
            elif line and not line.startswith("#"):
                segment_url = urljoin(base_url, line)
                line = f"/proxy/ts?url={quote(segment_url)}&{headers_query}"
            modified_m3u8.append(line)

        modified_m3u8_content = "\n".join(modified_m3u8)
        return Response(modified_m3u8_content, content_type="application/vnd.apple.mpegurl")

    except requests.RequestException as e:
        logger.info(f"Errore durante il download o la risoluzione del file: {str(e)}")
        return f"Errore durante il download o la risoluzione del file M3U/M3U8: {str(e)}", 500
    except Exception as e:
        logger.info(f"Errore generico nella funzione proxy_m3u: {str(e)}")
        return f"Errore generico durante l'elaborazione: {str(e)}", 500

@app.route('/proxy/resolve')
def proxy_resolve():
    """Proxy per risolvere e restituire un URL M3U8"""
    url = request.args.get('url', '').strip()
    if not url:
        return "Errore: Parametro 'url' mancante", 400

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        result = resolve_m3u8_link(url, headers)
        
        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL", 500
            
        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in result["headers"].items()])
        
        return Response(
            f"#EXTM3U\n"
            f"#EXTINF:-1,Canale Risolto\n"
            f"/proxy/m3u?url={quote(result['resolved_url'])}&{headers_query}",
            content_type="application/vnd.apple.mpegurl"
        )
        
    except Exception as e:
        return f"Errore durante la risoluzione dell'URL: {str(e)}", 500

@app.route('/proxy/ts')
def proxy_ts():
    """Proxy per segmenti .TS con headers personalizzati - SENZA CACHE"""
    ts_url = request.args.get('url', '').strip()
    if not ts_url:
        return "Errore: Parametro 'url' mancante", 400

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        # Stream diretto senza cache per evitare freezing
        response = requests.get(ts_url, headers=headers, stream=True, allow_redirects=True, timeout=(10, 30)) # Timeout di connessione 10s, lettura 30s
        response.raise_for_status()
        
        def generate():
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    yield chunk
        
        return Response(generate(), content_type="video/mp2t")
    
    except requests.RequestException as e:
        return f"Errore durante il download del segmento TS: {str(e)}", 500

@app.route('/proxy/key')
def proxy_key():
    """Proxy per la chiave AES-128 con header personalizzati"""
    key_url = request.args.get('url', '').strip()
    if not key_url:
        return "Errore: Parametro 'url' mancante per la chiave", 400

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        response = requests.get(key_url, headers=headers, allow_redirects=True, timeout=(5, 15)) # Timeout connessione 5s, lettura 15s
        response.raise_for_status()
        
        return Response(response.content, content_type="application/octet-stream")
    
    except requests.RequestException as e:
        return f"Errore durante il download della chiave AES-128: {str(e)}", 500

@app.route('/playlist/channels.m3u8')
def playlist_channels():
    """Fetches playlist from GitHub and proxies ALL URLs with headers"""
    playlist_url = "https://raw.githubusercontent.com/DeDuplicate/NewDadProxy/refs/heads/main/channel.m3u8"
    
    try:
        host_url = request.host_url.rstrip('/')
        response = requests.get(playlist_url, timeout=10)
        response.raise_for_status()
        playlist_content = response.text
        
        modified_lines = []
        current_headers = {}
        
        for line in playlist_content.splitlines():
            stripped_line = line.strip()
            
            # Extract headers from EXTVLCOPT lines
            if stripped_line.startswith('#EXTVLCOPT:http-referrer='):
                current_headers['Referer'] = stripped_line.replace('#EXTVLCOPT:http-referrer=', '')
            elif stripped_line.startswith('#EXTVLCOPT:http-origin='):
                current_headers['Origin'] = stripped_line.replace('#EXTVLCOPT:http-origin=', '')
            elif stripped_line.startswith('#EXTVLCOPT:http-user-agent='):
                current_headers['User-Agent'] = stripped_line.replace('#EXTVLCOPT:http-user-agent=', '')
            
            # Process URL lines
            if stripped_line and not stripped_line.startswith('#'):
                # Build proxy URL with headers
                proxy_url = f"{host_url}/proxy/m3u?url={quote(stripped_line)}"
                
                # Add headers as query parameters
                if current_headers:
                    for key, value in current_headers.items():
                        proxy_url += f"&h_{quote(key)}={quote(value)}"
                
                modified_lines.append(proxy_url)
                # Reset headers for next channel
                current_headers = {}
            else:
                # Keep metadata lines but skip EXTVLCOPT lines since we inject headers in proxy URL
                if not stripped_line.startswith('#EXTVLCOPT:'):
                    modified_lines.append(line)
        
        modified_content = '\n'.join(modified_lines)
        return Response(modified_content, content_type="application/vnd.apple.mpegurl")

    except requests.RequestException as e:
        logger.error(f"Error loading playlist: {str(e)}")
        return f"Error loading playlist: {str(e)}", 500
    except Exception as e:
        logger.error(f"General error: {str(e)}")
        return f"General error: {str(e)}", 500


@app.route('/playlist/events.m3u8')
def playlist_events():
    """Generiert die Events-Playlist mit Proxy-Links bei jedem Aufruf"""
    try:
        # Hole die aktuelle Host-URL
        host_url = request.host_url.rstrip('/')
        
        # Lade die Sendeplandaten
        schedule_data = fetch_schedule_data()
        if not schedule_data:
            return "Fehler beim Abrufen der Sendeplandaten", 500
        
        # Konvertiere JSON in M3U mit Proxy-Links
        m3u_content = json_to_m3u(schedule_data, host_url)
        if not m3u_content:
            return "Fehler beim Generieren der Playlist", 500
            
        return Response(m3u_content, content_type="application/vnd.apple.mpegurl")
    
    except Exception as e:
        logger.info(f"Fehler in /playlist/events: {str(e)}")
        return f"Interner Serverfehler: {str(e)}", 500

def fetch_schedule_data():
    """Holt die aktuellen Sendeplandaten von der Website"""
    url = "https://daddylive.sx/schedule/schedule-generated.php"
    headers = {
        "authority": "daddylive.sx",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "de-DE,de;q=0.9",
        "priority": "u=1, i",
        "referer": "https://daddylive.sx/",
        "sec-ch-ua": '"Brave";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-gpc": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()
        else:
            logger.info(f"Fehler beim Abrufen der Daten: Status-Code {response.status_code}")
            return None
    except Exception as e:
        logger.info(f"Fehler beim Abrufen der Daten: {e}")
        return None

def json_to_m3u(data, host_url):
    """Konvertiert JSON-Daten in M3U-Format mit Proxy-Links im gewünschten Format"""
    if not data:
        return None
        
    m3u_content = '#EXTM3U\n\n'
    
    try:
        main_key = list(data.keys())[0]
        categories = data[main_key]
    except Exception as e:
        logger.info(f"Fehler beim Verarbeiten der JSON-Daten: {e}")
        return None

    for category_name, events in categories.items():
        if not isinstance(events, list):
            continue
            
        for event in events:
            if not isinstance(event, dict):
                continue
                
            group_title = event.get("event", "Unknown Event")
            channels_list = []
            
            for channel_key in ["channels", "channels2"]:
                channels = event.get(channel_key, [])
                if isinstance(channels, dict):
                    channels_list.extend(channels.values())
                elif isinstance(channels, list):
                    channels_list.extend(channels)
            
            for channel in channels_list:
                if not isinstance(channel, dict):
                    continue
                    
                channel_name = channel.get("channel_name", "Unknown Channel")
                channel_id = channel.get("channel_id", "0")
                
                # Generiere die Stream-URL basierend auf der ID
                try:
                    channel_id_int = int(channel_id)
                    if channel_id_int > 999:
                        stream_url = f"https://daddylive.sx/stream/bet.php?id=bet{channel_id}"
                    else:
                        stream_url = f"https://daddylive.sx/stream/stream-{channel_id}.php"
                except (ValueError, TypeError):
                    stream_url = f"https://daddylive.sx/stream/stream-{channel_id}.php"
                
                # Generiere den Proxy-Link im gewünschten Format
                proxy_url = f"{host_url}/proxy/m3u?url={stream_url}"
                
                m3u_content += (
                    f'#EXTINF:-1 tvg-id="{channel_name}" group-title="{group_title}",{channel_name}\n'
                    '#EXTVLCOPT:http-referrer=https://forcedtoplay.xyz/\n'
                    '#EXTVLCOPT:http-origin=https://forcedtoplay.xyz\n'
                    '#EXTVLCOPT:http-user-agent=Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1\n'
                    f'{proxy_url}\n\n'
                )
    
    return m3u_content

@app.route('/')
def index():
    """Pagina principale che mostra un messaggio di benvenuto"""
    return "Proxy started!"

if __name__ == '__main__':
    logger.info("Proxy started!")
    app.run(host="0.0.0.0", port=7860, debug=False)
