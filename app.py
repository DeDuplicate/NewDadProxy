from flask import Flask, request, Response
import requests
from urllib.parse import urlparse, urljoin, quote, unquote
import re
import traceback
import os
import json
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

app = Flask(__name__)

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def detect_m3u_type(content):
    """Stricter detection: treat as HLS only if #EXTM3U and at least one #EXT-X- tag."""
    if "#EXTM3U" in content and re.search(r'^#EXT-X-', content, re.MULTILINE):
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

def get_all_player_cdns():
    """
    Returns comprehensive list of all known player CDN domains and patterns
    for easier proxy resolution and discovery
    """
    return {
        'newkso_cdns': [
            'top1.newkso.ru', 'top2.newkso.ru', 'top3.newkso.ru', 'top4.newkso.ru',
            'top1new.newkso.ru', 'top3new.newkso.ru', 'top4new.newkso.ru',
            'cdn1.newkso.ru', 'cdn2.newkso.ru', 'cdn1new.newkso.ru', 'cdn2new.newkso.ru',
            'windnew.newkso.ru', 'nfsnew.newkso.ru', 'zekonew.newkso.ru',
            'ddy1new.newkso.ru', 'ddy2new.newkso.ru', 'ddy3new.newkso.ru', 
            'ddy4new.newkso.ru', 'ddy5new.newkso.ru', 'ddy6new.newkso.ru', 
            'ddy7new.newkso.ru', 'ddy8new.newkso.ru'
        ],
        'vidembed_cdns': [
            'vidembed.re', 'vidembed.to', 'vidembed.cc', 'vidembed.me',
            'chinese-restaurant-api.site', 'happy-ending.site'
        ],
        'daddylive_domains': [
            'thedaddy.dad', 'thedaddy.click', 'daddylive.sx', 'daddylive.mp', 'dlhd.click'
        ],
        'stream_patterns': [
            '/embed/stream-', '/stream/stream-', '/cast/stream-', '/watch/stream-',
            '/d3.php', '/premiumtv/', '/auth.php', '/lookup'
        ],
        'm3u8_patterns': [
            '/mono.m3u8', '/premium{channel_id}/mono.m3u8', 
            '/{server_key}/{channel_id}/mono.m3u8'
        ]
    }

def resolve_m3u8_link(url, headers=None, debug=False):
    """
    Tenta di risolvere un URL M3U8.
    Prova prima la logica specifica per iframe (tipo Daddylive), inclusa la lookup della server_key.
    Se fallisce, verifica se l'URL iniziale era un M3U8 diretto e lo restituisce.
    Supporta anche URL diretti di VidEmbed.
    """
    if not url:
        logger.error("Error: URL not provided.")
        return {"resolved_url": None, "headers": {}}

    logger.info(f"Attempting to resolve URL: {url}")
    current_headers = headers if headers else {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0+Safari/537.36'}

    initial_response_text = None
    final_url_after_redirects = None
    
    # Enhanced CDN detection using comprehensive list
    cdn_config = get_all_player_cdns()
    is_daddylive = any(domain in url.lower() for domain in cdn_config['daddylive_domains'])
    is_vidembed_cdn = any(domain in url.lower() for domain in cdn_config['vidembed_cdns'] + cdn_config['newkso_cdns']) or '.m3u8' in url.lower()

    try:
        with requests.Session() as session:
            logger.info(f"Step 1: Request to {url}")
            if "daddylive.sx" in url.lower():
                url = url.replace("daddylive.sx", "thedaddy.dad")
                logger.info(f"Converted daddylive.sx to thedaddy.dad: {url}")
            response = session.get(url, headers=current_headers, allow_redirects=True, timeout=(5, 15))
            response.raise_for_status()
            initial_response_text = response.text
            final_url_after_redirects = response.url
            logger.info(f"Step 1 complete. Final URL after redirects: {final_url_after_redirects}")

            if is_vidembed_cdn:
                logger.info(f"Detected direct VidEmbed/CDN URL: {url}")
                if ".m3u8" in url.lower():
                    vidembed_headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
                        'Referer': 'https://www.vidembed.re/',
                        'Origin': 'https://www.vidembed.re',
                        'Accept': '*/*','Accept-Language': 'en-US,en;q=0.9','Accept-Encoding': 'gzip, deflate, br',
                        'Cache-Control': 'no-cache','Pragma': 'no-cache','Sec-Fetch-Dest': 'empty','Sec-Fetch-Mode': 'cors','Sec-Fetch-Site': 'cross-site'
                    }
                    return {"resolved_url": url, "headers": vidembed_headers}
                elif initial_response_text and initial_response_text.strip().startswith('#EXTM3U'):
                    return {"resolved_url": final_url_after_redirects, "headers": current_headers}

            if is_daddylive and initial_response_text and initial_response_text.strip().startswith('#EXTM3U'):
                return {"resolved_url": final_url_after_redirects, "headers": current_headers}
            if is_daddylive:
                logger.info(f"Daddylive URL is not a direct M3U8, attempting iframe logic: {url}")

            logger.info("Attempting iframe logic...")
            try:
                # Enhanced iframe detection with multiple patterns
                iframe_patterns = [
                    r'<iframe[^>]+src=["\']([^"\']+)["\']',  # Standard iframe
                    r'<iframe[^>]*src\s*=\s*["\']([^"\']+)["\']',  # With extra spaces
                    r'iframe.*?src.*?["\']([^"\']*jxoplay[^"\']*)["\']',  # Look for jxoplay specifically
                    r'iframe.*?src.*?["\']([^"\']*premiumtv[^"\']*)["\']',  # Look for premiumtv
                    r'<embed[^>]+src=["\']([^"\']+)["\']',  # Alternative embed tags
                    r'source.*?src.*?["\']([^"\']+)["\']',  # Source elements
                ]
                
                iframes = []
                content_to_search = initial_response_text or ''
                
                for pattern in iframe_patterns:
                    matches = re.findall(pattern, content_to_search, re.IGNORECASE | re.DOTALL)
                    if matches:
                        iframes.extend(matches)
                        logger.info(f"Found {len(matches)} iframe(s) with pattern: {pattern[:50]}...")
                
                # Additional search in script tags for dynamic iframe creation
                script_iframe_patterns = [
                    r'src\s*=\s*["\']([^"\']*jxoplay[^"\']*)["\']',
                    r'["\']([^"\']*premiumtv/daddyhd\.php[^"\']*)["\']',
                    r'iframe.*?["\']([^"\']*\.php\?id=\d+[^"\']*)["\']',
                ]
                
                for pattern in script_iframe_patterns:
                    matches = re.findall(pattern, content_to_search, re.IGNORECASE)
                    if matches:
                        iframes.extend(matches)
                        logger.info(f"Found {len(matches)} script iframe(s) with pattern: {pattern[:50]}...")
                
                # Remove duplicates and filter valid URLs
                unique_iframes = []
                for iframe in iframes:
                    if iframe and iframe.startswith(('http', '/')) and iframe not in unique_iframes:
                        unique_iframes.append(iframe)
                
                if not unique_iframes:
                    # Last resort: try to construct iframe URL based on channel ID
                    channel_match = re.search(r'stream-(\d+)\.php', url)
                    if channel_match:
                        channel_id = channel_match.group(1)
                        constructed_iframe = f"https://jxoplay.xyz/premiumtv/daddyhd.php?id={channel_id}"
                        logger.info(f"No iframe found, constructing from channel ID: {constructed_iframe}")
                        unique_iframes = [constructed_iframe]
                
                if not unique_iframes:
                    raise ValueError("No iframe src found after enhanced detection.")
                    
                url2 = unique_iframes[0]
                logger.info(f"Selected iframe URL: {url2}")
                logger.info(f"Step 2 (Iframe): Found iframe URL: {url2}")
                referer_raw = urlparse(url2).scheme + "://" + urlparse(url2).netloc + "/"
                origin_raw = urlparse(url2).scheme + "://" + urlparse(url2).netloc
                current_headers['Referer'] = referer_raw
                current_headers['Origin'] = origin_raw
                logger.info(f"Step 3 (Iframe): Request to {url2}")
                response = session.get(url2, headers=current_headers, timeout=(5, 15), verify=False)
                response.raise_for_status()
                iframe_response_text = response.text
                logger.info("Step 3 (Iframe) complete.")

                # Enhanced extraction helper (replaces previous inline definition)
                def extract_dynamic_params(text: str, iframe_url: str, session: requests.Session, headers: dict, debug_mode: bool=False):
                    import urllib.parse, base64
                    fetched_scripts = []
                    # Lazy import js2py only when needed
                    try:
                        import js2py  # noqa: F401
                        JS_AVAILABLE = True
                    except Exception:
                        JS_AVAILABLE = False

                    def absolutize(u: str):
                        try:
                            if u.startswith('http://') or u.startswith('https://'):
                                return u
                            if u.startswith('//'):
                                return urlparse(iframe_url).scheme + ':' + u
                            base = iframe_url.rsplit('/',1)[0] + '/'
                            return urllib.parse.urljoin(base, u)
                        except Exception:
                            return u

                    # Collect external script src URLs
                    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', text, re.IGNORECASE)
                    script_srcs = [absolutize(s) for s in script_srcs]
                    # Heuristic: prioritize same-domain first
                    iframe_domain = urlparse(iframe_url).netloc
                    script_srcs.sort(key=lambda s: (urlparse(s).netloc != iframe_domain, len(s)))

                    external_scripts_content = ''
                    for s_url in script_srcs[:8]:  # cap
                        try:
                            r_js = session.get(s_url, headers=headers, timeout=(4,10), verify=False)
                            if r_js.status_code == 200 and 'text' in r_js.headers.get('Content-Type',''):
                                c_js = r_js.text
                                # Skip very large ad libs
                                if len(c_js) < 400000:
                                    external_scripts_content += '\n/*EXTERNAL:'+s_url+'*/\n' + c_js
                                    fetched_scripts.append((s_url, len(c_js)))
                        except Exception as fe:
                            if debug_mode:
                                logger.info(f"External script fetch failed {s_url}: {fe}")

                    aggregated = text + ('\n' + external_scripts_content if external_scripts_content else '')

                    def run_primary_patterns(source_text: str):
                        patt_map = {
                            'channel_key': [r'channelKey\s*[:=]\s*["\']([^"\']+)["\']', r'channel_key\s*[:=]\s*["\']([^"\']+)["\']', r'\bchannelKey\b\s*=\s*["\']([^"\']+)', r'premium([0-9]{2,5})'],
                            'auth_ts': [r'authTs\s*[:=]\s*["\']([^"\']+)["\']', r'auth_ts\s*[:=]\s*["\']([^"\']+)["\']', r'(?:authTs|auth_ts)["\'\s:=]+([0-9]{10,})', r'"auth_ts"\s*:\s*"?([0-9]{10,})"?'],
                            'auth_rnd': [r'authRnd\s*[:=]\s*["\']([^"\']+)["\']', r'auth_rnd\s*[:=]\s*["\']([^"\']+)["\']', r'(?:authRnd|auth_rnd)["\'\s:=]+([0-9A-Za-z]{6,})', r'"auth_rnd"\s*:\s*"?([0-9A-Za-z]{6,})"?'],
                            'auth_sig': [r'authSig\s*[:=]\s*["\']([^"\']+)["\']', r'auth_sig\s*[:=]\s*["\']([^"\']+)["\']', r'(?:authSig|auth_sig)["\'\s:=]+([0-9A-Fa-f]{32,256})', r'"auth_sig"\s*:\s*"?([0-9A-Fa-f]{32,256})"?']
                        }
                        out_local = {}
                        for key, patterns in patt_map.items():
                            for p in patterns:
                                m = re.search(p, source_text)
                                if m:
                                    # Special handling for premium capture variant
                                    if key == 'channel_key' and p == 'premium([0-9]{2,5})':
                                        out_local[key] = 'premium' + m.group(1)
                                    else:
                                        out_local[key] = m.group(1)
                                    break
                        return out_local

                    out = run_primary_patterns(aggregated)

                    # Inline scripts extraction (existing logic retained)
                    inline_scripts = re.findall(r'<script(?:(?!src=)[^>])*>(.*?)</script>', text, re.IGNORECASE | re.DOTALL)
                    for scr in inline_scripts[:12]:
                        if len(scr) < 250000:
                            aggregated += '\n' + scr
                    if inline_scripts:
                        for k,v in run_primary_patterns(aggregated).items():
                            out.setdefault(k,v)

                    # Basic packed eval(function(p,a,c,k) detection and unpacking
                    if 'eval(function(p,a,c,k' in aggregated or 'eval(function(p,a,c,k,e' in aggregated:
                        if debug_mode:
                            logger.info('Detected packed eval pattern - attempting to unpack')
                        packed_matches = re.findall(r"eval\(function\(p,a,c,k,e,d\).*?\('([^']+)',([0-9]+),([0-9]+),'([^']+)'\.split\('\|'\)", aggregated, re.DOTALL)
                        for packed_code, p, a, keywords in packed_matches:
                            try:
                                # Simple P.A.C.K.E.R unpacker
                                keywords_list = keywords.split('|')
                                unpacked = packed_code
                                # Replace encoded tokens with actual values
                                for i, keyword in enumerate(keywords_list):
                                    if keyword:
                                        # Convert index to base-36 if needed
                                        token = ''
                                        if i < int(a):
                                            if i < 10:
                                                token = str(i)
                                            else:
                                                token = chr(ord('a') + i - 10)
                                        else:
                                            token = str(i)
                                        unpacked = unpacked.replace(f'\\b{token}\\b', keyword)
                                aggregated += '\n/*UNPACKED*/\n' + unpacked
                                if debug_mode:
                                    logger.info(f'Successfully unpacked {len(unpacked)} chars of packed code')
                            except Exception as unpack_err:
                                if debug_mode:
                                    logger.info(f'Unpacking failed: {unpack_err}')
                    
                    # Extract window assignments for auth parameters
                    window_patterns = [
                        r'window\[["\']?(authTs|auth_ts)["\']?\]\s*=\s*["\']?([^"\';\s]+)["\']?',
                        r'window\[["\']?(authRnd|auth_rnd)["\']?\]\s*=\s*["\']?([^"\';\s]+)["\']?',
                        r'window\[["\']?(authSig|auth_sig)["\']?\]\s*=\s*["\']?([^"\';\s]+)["\']?',
                        r'window\[["\']?(channelKey|channel_key)["\']?\]\s*=\s*["\']?([^"\';\s]+)["\']?',
                        r'window\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']?([^"\';\s]+)["\']?'
                    ]
                    for pattern in window_patterns:
                        matches = re.findall(pattern, aggregated)
                        for key, value in matches:
                            key_lower = key.lower()
                            if 'authts' in key_lower or 'auth_ts' in key_lower:
                                out.setdefault('auth_ts', value)
                            elif 'authrnd' in key_lower or 'auth_rnd' in key_lower:
                                out.setdefault('auth_rnd', value)
                            elif 'authsig' in key_lower or 'auth_sig' in key_lower:
                                out.setdefault('auth_sig', value)
                            elif 'channelkey' in key_lower or 'channel_key' in key_lower:
                                out.setdefault('channel_key', value)
                    
                    # Extract from setTimeout/setInterval string arguments
                    timeout_patterns = re.findall(r'setTimeout\(["\']([^"\']+)["\']', aggregated)
                    timeout_patterns.extend(re.findall(r'setInterval\(["\']([^"\']+)["\']', aggregated))
                    for timeout_code in timeout_patterns:
                        if any(x in timeout_code for x in ['authTs','auth_ts','authSig','auth_sig','authRnd','auth_rnd','channelKey']):
                            aggregated += '\n/*TIMEOUT_CODE*/\n' + timeout_code
                    
                    # Re-run patterns after unpacking and window extraction
                    for k,v in run_primary_patterns(aggregated).items():
                        out.setdefault(k,v)

                    # Enhanced Base64 atob decode with variable assignment tracking
                    # Look for var assignments with atob
                    atob_vars = {}
                    var_atob_matches = re.findall(r'var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*atob\(\s*["\']([A-Za-z0-9+/=]+)["\']', aggregated)
                    for var_name, b64_content in var_atob_matches:
                        try:
                            decoded = base64.b64decode(b64_content).decode('utf-8', errors='ignore')
                            atob_vars[var_name] = decoded
                            if debug_mode:
                                logger.info(f"Decoded atob var {var_name}: {decoded[:50]}...")
                        except Exception:
                            pass
                    
                    # Look for common authentication variable patterns with atob
                    auth_atob_patterns = [
                        (r'var\s+__([a-zA-Z])\s*=\s*atob\(\s*["\']([A-Za-z0-9+/=]+)["\']', 'single_letter'),
                        (r'var\s+(auth[a-zA-Z]*|channel[a-zA-Z]*|__[a-zA-Z]*)\s*=\s*atob\(\s*["\']([A-Za-z0-9+/=]+)["\']', 'auth_vars'),
                    ]
                    
                    for pattern, pattern_type in auth_atob_patterns:
                        matches = re.findall(pattern, aggregated)
                        for var_name, b64_content in matches:
                            try:
                                decoded = base64.b64decode(b64_content).decode('utf-8', errors='ignore')
                                if debug_mode:
                                    logger.info(f"Auth atob decode {var_name}: {decoded}")
                                # Map specific patterns to auth parameters
                                if pattern_type == 'single_letter':
                                    # Common single letter pattern mappings based on observed patterns
                                    if var_name == 'c' and decoded.isdigit() and len(decoded) == 10:  # TS pattern
                                        out.setdefault('auth_ts', decoded)
                                    elif var_name == 'd' and len(decoded) == 8 and re.match(r'[a-f0-9]+', decoded):  # RND pattern
                                        out.setdefault('auth_rnd', decoded)
                                    elif var_name == 'e' and len(decoded) >= 32 and re.match(r'[a-f0-9]+', decoded):  # SIG pattern
                                        out.setdefault('auth_sig', decoded)
                                    elif var_name == 'a' and 'http' in decoded:  # URL pattern
                                        out.setdefault('base_url', decoded)
                                    elif var_name == 'b' and '.php' in decoded:  # Endpoint pattern
                                        out.setdefault('auth_endpoint', decoded)
                                    # Generic fallback patterns
                                    elif len(decoded) == 8 and re.match(r'[a-f0-9]+', decoded):  # RND pattern
                                        out.setdefault('auth_rnd', decoded)
                                    elif decoded.isdigit() and len(decoded) == 10:  # TS pattern
                                        out.setdefault('auth_ts', decoded)
                                    elif len(decoded) >= 32 and re.match(r'[a-f0-9]+', decoded):  # SIG pattern
                                        out.setdefault('auth_sig', decoded)
                                    elif 'http' in decoded:  # URL pattern
                                        out.setdefault('base_url', decoded)
                                    elif '.php' in decoded:  # Endpoint pattern
                                        out.setdefault('auth_endpoint', decoded)
                            except Exception as e:
                                if debug_mode:
                                    logger.info(f"Base64 decode failed for {var_name}: {e}")
                    
                    # Look for buildAuthUrl function and extract the pattern
                    build_auth_match = re.search(r'function\s+buildAuthUrl\s*\(\)\s*\{[^}]*return\s+([^;]+)', aggregated, re.DOTALL)
                    if build_auth_match:
                        build_pattern = build_auth_match.group(1)
                        if debug_mode:
                            logger.info(f"Found buildAuthUrl pattern: {build_pattern}")
                        # Extract variable references in the buildAuthUrl pattern
                        var_refs = re.findall(r'__([a-zA-Z])', build_pattern)
                        for var_ref in var_refs:
                            if f'__{var_ref}' in atob_vars:
                                decoded = atob_vars[f'__{var_ref}']
                                if debug_mode:
                                    logger.info(f"Auth var __{var_ref}: {decoded}")
                    
                    # Specific base64 value detection for known auth parameters
                    known_b64_patterns = {
                        'ZmYwYzc4YzY=': 'auth_rnd',  # ff0c78c6
                        'MTc1NDgxNjk3MA==': 'auth_ts',  # 1754816970
                        'OWE5MDMxY2NmZjgwYjViZmRiMWMyOWFmNmJiNjQxMDNmOWM0YzQyY2MxNDJhNWM2Y2VkZGU0MWQ1M2JhOTk5Zg==': 'auth_sig',  # 9a9031ccff80b5bfdb1c29af6bb64103f9c4c42cc142a5c6cedde41d53ba999f
                        'aHR0cHM6Ly90b3AybmV3Lm5ld2tzby5ydS8=': 'base_url',  # https://top2new.newkso.ru/
                        'YXV0aC5waHA=': 'auth_endpoint',  # auth.php
                    }
                    
                    for b64_val, param_name in known_b64_patterns.items():
                        if b64_val in aggregated:
                            try:
                                decoded = base64.b64decode(b64_val).decode('utf-8')
                                out.setdefault(param_name, decoded)
                                if debug_mode:
                                    logger.info(f"Found known pattern {param_name}: {decoded}")
                            except Exception:
                                pass
                    
                    # General base64 candidates
                    b64_candidates = re.findall(r"atob\(['\"]([A-Za-z0-9+/=]{16,})['\"]\)", aggregated)
                    for b64 in b64_candidates[:30]:
                        try:
                            dec = base64.b64decode(b64 + '===').decode('utf-8', errors='ignore')
                            if any(x in dec for x in ['authTs','auth_ts','authSig','auth_sig','authRnd','auth_rnd','channelKey']):
                                aggregated += '\n' + dec
                        except Exception:
                            continue
                    for k,v in run_primary_patterns(aggregated).items():
                        out.setdefault(k,v)

                    # fetch / URL patterns
                    fetch_urls = re.findall(r'fetchWithRetry\(\s*["\']([^"\']+)["\']', aggregated)
                    if not fetch_urls:
                        fetch_urls = re.findall(r'fetch\(\s*["\']([^"\']+)["\']', aggregated)

                    def parse_auth_from_urls(url_list):
                        for u in url_list:
                            lower = u.lower()
                            if 'auth' in lower:
                                parsed = urllib.parse.urlparse(u)
                                qs = urllib.parse.parse_qs(parsed.query)
                                def first(k):
                                    return qs.get(k,[None])[0]
                                ts = first('ts') or first('timestamp')
                                rnd = first('rnd') or first('r')
                                sig = first('sig') or first('signature')
                                if ts and 'auth_ts' not in out:
                                    out['auth_ts'] = ts
                                if rnd and 'auth_rnd' not in out:
                                    out['auth_rnd'] = rnd
                                if sig and 'auth_sig' not in out:
                                    out['auth_sig'] = sig
                    parse_auth_from_urls(fetch_urls)

                    auth_host = next((u for u in fetch_urls if 'auth' in u.lower()), fetch_urls[0] if fetch_urls else None)
                    server_lookup = next((u for u in fetch_urls if 'lookup' in u.lower() or 'server' in u.lower()), None)
                    if not server_lookup and len(fetch_urls) > 1:
                        server_lookup = fetch_urls[1]
                    if auth_host:
                        out['auth_host'] = auth_host
                    if server_lookup:
                        out['server_lookup'] = server_lookup

                    # Derive channel_key from iframe query id parameter if missing
                    if 'channel_key' not in out:
                        try:
                            qsp = urllib.parse.parse_qs(urllib.parse.urlparse(iframe_url).query)
                            cid = qsp.get('id',[None])[0]
                            if cid:
                                out['channel_key'] = cid
                        except Exception:
                            pass

                    # Attempt to capture concatenated premium channelKey pattern
                    if 'channel_key' in out and not out['channel_key'].startswith('premium') and re.search(r'premium'+re.escape(out['channel_key']), aggregated):
                        out['channel_key'] = 'premium' + out['channel_key']

                    # JS mini-eval improvement (only simple lines)
                    if any(k not in out for k in ['auth_ts','auth_rnd','auth_sig']) and JS_AVAILABLE:
                        assign_lines = []
                        for line in aggregated.splitlines():
                            if any(tok in line for tok in ['authTs','auth_ts','authSig','auth_sig','authRnd','auth_rnd','channelKey','channel_key']):
                                if re.search(r'(var|let|const)?\s*(authTs|auth_ts|authSig|auth_sig|authRnd|auth_rnd|channelKey|channel_key)\s*=\s*', line):
                                    cleaned = line.split('//')[0].strip()
                                    if not re.search(r'function|=>|if\s*\(|while\s*\(|for\s*\(', cleaned) and len(cleaned) < 400:
                                        # Remove trailing semicolons
                                        assign_lines.append(cleaned.rstrip(';'))
                        if assign_lines:
                            js_code = '\n'.join(assign_lines) + '\n'
                            js_code = 'var Date = { now: function(){ return '+str(int(__import__("time").time()))+'; }};\n' + js_code
                            js_code += 'var __out = {authTs: (typeof authTs!="undefined"?authTs:(typeof auth_ts!="undefined"?auth_ts:null)), authRnd:(typeof authRnd!="undefined"?authRnd:(typeof auth_rnd!="undefined"?auth_rnd:null)), authSig:(typeof authSig!="undefined"?authSig:(typeof auth_sig!="undefined"?auth_sig:null)), channelKey:(typeof channelKey!="undefined"?channelKey:(typeof channel_key!="undefined"?channel_key:null))};'
                            try:
                                import js2py
                                if len(js_code) < 60000:
                                    ctx = js2py.EvalJs({})
                                    ctx.execute(js_code)
                                    extracted = getattr(ctx, '__out', None)
                                    if extracted:
                                        if getattr(extracted,'authTs',None) and 'auth_ts' not in out:
                                            out['auth_ts'] = str(extracted.authTs)
                                        if getattr(extracted,'authRnd',None) and 'auth_rnd' not in out:
                                            out['auth_rnd'] = str(extracted.authRnd)
                                        if getattr(extracted,'authSig',None) and 'auth_sig' not in out:
                                            out['auth_sig'] = str(extracted.authSig)
                                        if getattr(extracted,'channelKey',None) and 'channel_key' not in out:
                                            out['channel_key'] = str(extracted.channelKey)
                            except Exception as je:
                                if debug_mode:
                                    logger.info(f"JS eval extension failed: {je}")

                    # Auth probing expansion
                    if any(k not in out for k in ['auth_ts','auth_rnd','auth_sig']) and 'channel_key' in out:
                        iframe_parsed = urlparse(iframe_url)
                        base_dir = iframe_parsed.scheme + '://' + iframe_parsed.netloc + iframe_parsed.path.rsplit('/',1)[0] + '/'
                        candidates = [
                            'auth.php','auth','get_auth.php','gen_auth.php','premiumtv/auth.php','/auth.php','/premiumtv/auth.php',
                            'premiumtv/get_auth.php','auth2.php','premiumtv/auth2.php','api/auth.php'
                        ]
                        # also attempt with premium prefix variant if numeric
                        alt_keys = [out['channel_key']]
                        if re.match(r'^[0-9]{2,5}$', out['channel_key']):
                            alt_keys.append('premium'+out['channel_key'])
                        for ep in candidates:
                            for ck in alt_keys:
                                try:
                                    if ep.startswith('/'):
                                        cand = iframe_parsed.scheme + '://' + iframe_parsed.netloc + ep
                                    else:
                                        cand = base_dir + ep
                                    if '?' not in cand:
                                        cand_q = cand + '?channelKey=' + ck
                                    else:
                                        cand_q = cand + '&channelKey=' + ck
                                    r = session.get(cand_q, headers=headers, timeout=(4,8), verify=False)
                                    if r.status_code == 200 and len(r.text) < 8000:
                                        txt = r.text
                                        try:
                                            jdata = r.json()
                                        except Exception:
                                            jdata = {}
                                        def grab(klist):
                                            for kk in klist:
                                                if kk in jdata and jdata[kk]:
                                                    return str(jdata[kk])
                                            for kk in klist:
                                                m = re.search(kk + r'=?([0-9A-Za-z]{6,})', txt)
                                                if m:
                                                    return m.group(1)
                                            return None
                                        ts_val = grab(['auth_ts','ts'])
                                        rnd_val = grab(['auth_rnd','rnd','r'])
                                        sig_val = grab(['auth_sig','sig','signature'])
                                        if ts_val and rnd_val and sig_val:
                                            out.setdefault('auth_ts', ts_val)
                                            out.setdefault('auth_rnd', rnd_val)
                                            out.setdefault('auth_sig', sig_val)
                                            out.setdefault('auth_host', cand_q.split('channelKey=')[0] + 'channelKey=')
                                            logger.info(f"Auth probe succeeded via {cand_q}")
                                            break
                                except Exception as probe_exc:
                                    if debug_mode:
                                        logger.info(f"Auth probe error {ep}: {probe_exc}")
                            if all(k in out for k in ['auth_ts','auth_rnd','auth_sig','auth_host']):
                                break

                    required_core = ['channel_key','auth_ts','auth_rnd','auth_sig','auth_host','server_lookup']
                    missing = [k for k in required_core if k not in out or not out[k]]
                    if debug_mode:
                        try:
                            dump_id = out.get('channel_key','unknown')
                            dump_path = f"/tmp/iframe_debug_{dump_id}.txt"
                            with open(dump_path,'w',encoding='utf-8',errors='ignore') as fh:
                                fh.write('=== FETCHED SCRIPTS ===\n')
                                for su,ll in fetched_scripts:
                                    fh.write(f"{su} ({ll} bytes)\n")
                                fh.write('\n=== AGGREGATED (truncated) ===\n')
                                fh.write(aggregated[:500000])
                            logger.info(f"Debug dump written: {dump_path}")
                        except Exception as dump_exc:
                            logger.info(f"Debug dump failed: {dump_exc}")
                    if missing:
                        snippet = aggregated[:400].replace('\n',' ')
                        logger.info(f"Param extraction failed (extended v3), missing {missing}. fetch_urls={fetch_urls}. Scripts={len(fetched_scripts)} Snippet: {snippet}")
                        raise ValueError(f"Missing params: {missing}")
                    return out

                params = extract_dynamic_params(iframe_response_text, url2, session, current_headers, debug_mode=debug)
                channel_key = params['channel_key']
                auth_ts = params['auth_ts']
                auth_rnd = params['auth_rnd']
                auth_sig = quote(params['auth_sig'])
                auth_host = params['auth_host']
                server_lookup = params['server_lookup']
                
                # Log extracted parameters for debugging
                logger.info(f"Extracted parameters - channel_key: {channel_key}, auth_ts: {auth_ts}, auth_rnd: {auth_rnd}, auth_sig: {auth_sig[:20]}..., auth_host: {auth_host}, server_lookup: {server_lookup}")

                if not auth_host.endswith('&') and not auth_host.endswith('?'):
                    sep = '&' if ('?' in auth_host) else '?'
                    if 'channelKey=' not in auth_host and '{channelKey}' not in auth_host:
                        auth_host = f"{auth_host}{sep}channelKey="

                # Enhanced authentication URL construction with multiple server fallback
                auth_servers = [
                    'https://top2new.newkso.ru/auth.php',
                    'https://top1new.newkso.ru/auth.php', 
                    'https://top3new.newkso.ru/auth.php',
                    'https://windnew.newkso.ru/auth.php',
                    'https://nfsnew.newkso.ru/auth.php'
                ]
                
                auth_successful = False
                for auth_server in auth_servers:
                    try:
                        auth_url = f'{auth_server}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
                        logger.info(f"Step 5 (Iframe): Trying authentication server: {auth_url}")
                        
                        # Use enhanced headers for auth request
                        auth_headers = current_headers.copy()
                        auth_headers.update({
                            'Accept': 'application/json, text/plain, */*',
                            'X-Requested-With': 'XMLHttpRequest'
                        })
                        
                        auth_response = session.get(auth_url, headers=auth_headers, timeout=(5, 15), verify=False)
                        auth_response.raise_for_status()
                        
                        logger.info(f"Step 5 (Iframe) complete with server: {auth_server}")
                        auth_successful = True
                        break
                        
                    except requests.exceptions.RequestException as e:
                        logger.info(f"Auth server {auth_server} failed: {e}")
                        continue
                
                if not auth_successful:
                    raise ValueError("All authentication servers failed")

                if server_lookup.startswith('/'):
                    server_lookup_url = f"https://{urlparse(url2).netloc}{server_lookup}{channel_key}"
                elif server_lookup.startswith('http'):
                    server_lookup_url = f"{server_lookup}{channel_key}" if server_lookup.endswith('/') else f"{server_lookup}{channel_key}"
                else:
                    server_lookup_url = f"https://{urlparse(url2).netloc}/{server_lookup}{channel_key}"
                logger.info(f"Step 6 (Iframe): Server lookup request to {server_lookup_url}")
                server_lookup_response = session.get(server_lookup_url, headers=current_headers, timeout=(5, 15), verify=False)
                server_lookup_response.raise_for_status()
                server_key = None
                try:
                    server_lookup_data = server_lookup_response.json()
                    server_key = server_lookup_data.get('server_key') or server_lookup_data.get('serverKey')
                except Exception:
                    txt = server_lookup_response.text
                    mkey = re.search(r'server_key["\']?\s*[:=]\s*["\']([^"\']+)["\']', txt)
                    if mkey:
                        server_key = mkey.group(1)
                if not server_key:
                    raise ValueError("'server_key' non trovato nella risposta di server lookup.")
                logger.info(f"Step 7 (Iframe): Extracted server_key: {server_key}")

                # Enhanced M3U8 URL construction based on server_key
                if server_key == "top1/cdn":
                    final_stream_url = f'https://top1.newkso.ru/top1/cdn/{channel_key}/mono.m3u8'
                else:
                    final_stream_url = f'https://{server_key}.newkso.ru/{server_key}/{channel_key}/mono.m3u8'
                
                logger.info(f"Step 8 (Iframe): Constructed final M3U8 URL: {final_stream_url}")
                stream_headers = {'User-Agent': current_headers.get('User-Agent',''), 'Referer': referer_raw, 'Origin': origin_raw}
                return {"resolved_url": final_stream_url, "headers": stream_headers}

            except (ValueError, requests.exceptions.RequestException) as e:
                logger.info(f"Iframe logic failed: {e}")
                logger.info("Fallback attempt: checking if initial URL was a direct M3U8...")
                if initial_response_text and initial_response_text.strip().startswith('#EXTM3U'):
                    logger.info("Fallback succeeded: Found direct M3U8 file.")
                    return {"resolved_url": final_url_after_redirects, "headers": current_headers}
                else:
                    logger.info("Fallback failed: Initial response was not a direct M3U8.")
                    # For daddylive sites, try alternative resolution methods
                    if is_daddylive:
                        logger.info("Trying alternative resolution methods for DaddyLive...")
                        
                        # Method 0: Try direct URL construction without authentication (fastest)
                        channel_match = re.search(r'stream-(\d+)\.php', url)
                        if channel_match:
                            channel_id = channel_match.group(1)
                            logger.info(f"Extracted channel ID: {channel_id}")
                            
                            # Try known working patterns first - expanded list for better chances
                            priority_cdns = [
                                f"https://zekonew.newkso.ru/zeko/premium{channel_id}/mono.m3u8",
                                f"https://nfsnew.newkso.ru/nfs/premium{channel_id}/mono.m3u8", 
                                f"https://windnew.newkso.ru/wind/premium{channel_id}/mono.m3u8",
                                f"https://ddy1new.newkso.ru/ddy1/premium{channel_id}/mono.m3u8",
                                f"https://ddy2new.newkso.ru/ddy2/premium{channel_id}/mono.m3u8",
                                f"https://ddy3new.newkso.ru/ddy3/premium{channel_id}/mono.m3u8",
                                f"https://ddy4new.newkso.ru/ddy4/premium{channel_id}/mono.m3u8",
                                f"https://ddy5new.newkso.ru/ddy5/premium{channel_id}/mono.m3u8",
                                f"https://top1.newkso.ru/top1/cdn/premium{channel_id}/mono.m3u8",
                                f"https://top2.newkso.ru/top2/premium{channel_id}/mono.m3u8"
                            ]
                            
                            logger.info("Trying priority CDN patterns (no auth required)...")
                            
                            # Multiple header strategies for bypassing IP blocks
                            header_strategies = [
                                {
                                    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
                                    'Referer': 'https://jxoplay.xyz/premiumtv/',
                                    'Origin': 'https://jxoplay.xyz'
                                },
                                {
                                    'User-Agent': 'Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/118.0',
                                    'Referer': 'https://forcedtoplay.xyz/',
                                    'Origin': 'https://forcedtoplay.xyz'
                                },
                                {
                                    'User-Agent': 'VLC/3.0.18 LibVLC/3.0.18',
                                    'Referer': 'https://jxoplay.xyz/'
                                }
                            ]
                            
                            # Try each CDN with each header strategy
                            for priority_url in priority_cdns:
                                for strategy in header_strategies:
                                    try:
                                        test_response = session.head(priority_url, headers=strategy, timeout=2, verify=False)
                                        if test_response.status_code in [200, 206]:
                                            logger.info(f"Priority CDN successful (no auth): {priority_url}")
                                            return {"resolved_url": priority_url, "headers": strategy}
                                    except Exception:
                                        continue
                        
                        # Method 1: Try different auth servers
                        alternative_servers = [
                            "https://top1new.newkso.ru",
                            "https://top3new.newkso.ru", 
                            "https://top4new.newkso.ru",
                            "https://cdn1new.newkso.ru",
                            "https://cdn2new.newkso.ru"
                        ]
                        
                        # Extract channel ID from original URL
                        channel_match = re.search(r'stream-(\d+)\.php', url)
                        if channel_match:
                            channel_id = channel_match.group(1)
                            logger.info(f"Extracted channel ID: {channel_id}")
                            
                            # Method 2: Generate direct M3U8 construction patterns using CDN config
                            cdn_config = get_all_player_cdns()
                            direct_patterns = []
                            
                            # Generate patterns from newkso CDNs
                            for cdn in cdn_config['newkso_cdns']:
                                if 'top1.newkso.ru' in cdn:
                                    direct_patterns.append(f"https://{cdn}/top1/cdn/premium{channel_id}/mono.m3u8")
                                else:
                                    # Extract server key from CDN domain
                                    server_key = cdn.split('.')[0]
                                    if server_key.endswith('new'):
                                        server_key = server_key[:-3]  # Remove 'new' suffix
                                    direct_patterns.append(f"https://{cdn}/{server_key}/premium{channel_id}/mono.m3u8")
                            
                            # Add some additional common patterns
                            extra_patterns = [
                                f"https://top2new.newkso.ru/top2/premium{channel_id}/mono.m3u8",
                                f"https://streamnew.newkso.ru/stream/premium{channel_id}/mono.m3u8",
                                f"https://livednew.newkso.ru/lived/premium{channel_id}/mono.m3u8"
                            ]
                            direct_patterns.extend(extra_patterns)
                            
                            logger.info("Trying direct M3U8 URL patterns with enhanced strategy...")
                            
                            # Try patterns with different request strategies
                            for pattern_url in direct_patterns[:15]:  # Limit to first 15 for faster response
                                for strategy in ['head', 'get_partial']:
                                    try:
                                        test_headers = {
                                            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
                                            'Referer': 'https://jxoplay.xyz/premiumtv/',
                                            'Origin': 'https://jxoplay.xyz',
                                            'Accept': '*/*',
                                            'Cache-Control': 'no-cache'
                                        }
                                        
                                        if strategy == 'head':
                                            test_response = session.head(pattern_url, headers=test_headers, timeout=3, verify=False)
                                        else:  # get_partial - get with range to test quickly
                                            test_headers['Range'] = 'bytes=0-1023'
                                            test_response = session.get(pattern_url, headers=test_headers, timeout=3, verify=False)
                                        
                                        if test_response.status_code in [200, 206, 302]:
                                            logger.info(f"Direct pattern successful ({strategy}): {pattern_url}")
                                            return {"resolved_url": pattern_url, "headers": test_headers}
                                            
                                    except Exception as test_e:
                                        if 'timeout' not in str(test_e).lower():
                                            logger.info(f"Direct pattern failed {pattern_url} ({strategy}): {test_e}")
                                        continue
                                    
                                    # If head worked, don't try get_partial for same URL
                                    if strategy == 'head' and test_response.status_code in [200, 206]:
                                        break
                        
                        logger.info("All alternative methods failed - returning None")
                        return {"resolved_url": None, "headers": current_headers}
                    return {"resolved_url": url, "headers": current_headers}
    except requests.exceptions.RequestException as e:
        logger.info(f"Error during initial HTTP request: {e}")
        return {"resolved_url": url, "headers": current_headers}
    except Exception as e:
        logger.info(f"General error during resolution: {e}")
        return {"resolved_url": url, "headers": current_headers}

@app.route('/proxy')
def proxy():
    """Proxy per liste M3U che aggiunge automaticamente /m3u?url= con IP prima dei link"""
    m3u_url = unquote(request.args.get('url', '').strip())
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
    m3u_url = unquote(request.args.get('url', '').strip())
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400
    debug_mode = request.args.get('debug','').lower() in ('1','true','yes')
    # Enhanced headers to bypass IP blocking
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
        "Referer": "https://jxoplay.xyz/premiumtv/",
        "Origin": "https://jxoplay.xyz",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
        "Cache-Control": "max-age=0"
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
    cdn_config = get_all_player_cdns()
    all_cdn_domains = cdn_config['vidembed_cdns'] + cdn_config['newkso_cdns']
    is_direct_m3u8 = any(domain in m3u_url.lower() for domain in all_cdn_domains) and ".m3u8" in m3u_url.lower()
    
    # Special handling for happy-ending.site URLs with JWT auth
    is_happy_ending_jwt = "happy-ending.site" in m3u_url.lower() and ("?auth=" in m3u_url or "&auth=" in m3u_url)
    
    if is_direct_m3u8 or is_happy_ending_jwt:
        logger.info(f"Rilevato URL M3U8 diretto VidEmbed: {m3u_url}")
        processed_url = m3u_url  # Use the M3U8 URL directly
    # Trasforma vari pattern in /embed/ per Daddylive
    elif any(domain in m3u_url for domain in cdn_config['daddylive_domains']):
        if '/stream/stream-' in m3u_url:
            processed_url = m3u_url.replace('/stream/stream-', '/embed/stream-')
            logger.info(f"URL {m3u_url} trasformato da /stream/ a /embed/: {processed_url}")
        elif '/cast/stream-' in m3u_url:
            processed_url = m3u_url.replace('/cast/stream-', '/embed/stream-')
            logger.info(f"URL {m3u_url} trasformato da /cast/ a /embed/: {processed_url}")
        elif '/watch/stream-' in m3u_url:
            processed_url = m3u_url.replace('/watch/stream-', '/embed/stream-')
            logger.info(f"URL {m3u_url} trasformato da /watch/ a /embed/: {processed_url}")
        else:
            processed_url = m3u_url
            logger.info(f"URL {processed_url} DaddyLive processato senza trasformazione.")
    else:
        # Check for premium pattern transformation
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
        if is_direct_m3u8 or is_happy_ending_jwt:
            # Direct M3U8 URL or happy-ending.site JWT URL - just fetch it without resolving
            logger.info(f"Direct M3U8/JWT URL detected, fetching content directly: {processed_url}")
            
            # For happy-ending.site JWT URLs, use specific headers
            if is_happy_ending_jwt:
                jwt_headers = {
                    'User-Agent': headers.get('User-Agent', ''),
                    'Referer': 'https://kleanplay.shop/',
                    'Origin': 'https://kleanplay.shop',
                    'Accept': '*/*',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache'
                }
                m3u_response = requests.get(processed_url, headers=jwt_headers, allow_redirects=True, timeout=(10, 20))
            else:
                m3u_response = requests.get(processed_url, headers=headers, allow_redirects=True, timeout=(10, 20))
            
            m3u_response.raise_for_status()
            m3u_content = m3u_response.text
            final_url = m3u_response.url
            current_headers_for_proxy = headers
        else:
            # Stream URL that needs to be resolved to M3U8
            logger.info(f"Calling resolve_m3u8_link for processed URL: {processed_url}")
            result = resolve_m3u8_link(processed_url, headers, debug=debug_mode)

            if not result["resolved_url"]:
                return "Errore: Impossibile risolvere l'URL in un M3U8 valido.", 500

            resolved_url = result["resolved_url"]
            current_headers_for_proxy = result["headers"]

            logger.info(f"Resolution complete. Final M3U8 URL: {resolved_url}")

            # Fetchare il contenuto M3U8 effettivo dall'URL risolto
            logger.info(f"Fetching M3U8 content from resolved URL: {resolved_url}")
            m3u_response = requests.get(resolved_url, headers=current_headers_for_proxy, allow_redirects=True, timeout=(10, 45)) # Timeout connessione 10s, lettura 45s
            m3u_response.raise_for_status()
            m3u_content = m3u_response.text
            final_url = m3u_response.url

        # Validate that we actually got M3U8 content, not HTML
        if not m3u_content.strip().startswith('#EXTM3U') and not resolved_url.lower().endswith('.m3u8'):
            logger.info(f"Error: Fetched content is not M3U8 format. Content starts with: {m3u_content[:200]}")
            return "Error: Failed to resolve to valid M3U8 playlist. The stream may be protected or unavailable.", 502

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
        
        content_bytes = modified_m3u8_content.encode('utf-8')

        # Handle Range requests for VLC compatibility
        range_header = request.headers.get('Range')
        if range_header and range_header.startswith('bytes='):
            try:
                range_spec = range_header[6:]  # Remove "bytes="
                if '-' in range_spec:
                    start_str, end_str = range_spec.split('-', 1)
                    start = int(start_str) if start_str else 0
                    end = int(end_str) if end_str else len(content_bytes) - 1
                    
                    if start >= len(content_bytes):
                        return Response('Range Not Satisfiable', status=416)
                    
                    end = min(end, len(content_bytes) - 1)
                    partial_content = content_bytes[start:end+1]
                    
                    response_headers = {
                        'Content-Type': 'application/vnd.apple.mpegurl; charset=utf-8',
                        'Content-Length': str(len(partial_content)),
                        'Content-Range': f'bytes {start}-{end}/{len(content_bytes)}',
                        'Accept-Ranges': 'bytes',
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET, OPTIONS',
                        'Access-Control-Allow-Headers': 'Range, User-Agent, Content-Type',
                    }
                    
                    logger.info(f"Serving partial content for proxied M3U8: bytes {start}-{end}/{len(content_bytes)}")
                    return Response(partial_content, status=206, headers=response_headers)
            except (ValueError, IndexError):
                logger.info("Invalid range header for proxied M3U8, serving full content")
        
        # For VLC, ensure we return proper status and headers for full responses too
        response_headers = {
            'Content-Type': 'application/x-mpegURL',
            'Content-Length': str(len(content_bytes)),
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Range, User-Agent, Content-Type',
            'Accept-Ranges': 'bytes',
        }
        return Response(content_bytes, status=200, headers=response_headers)

    except requests.RequestException as e:
        logger.info(f"Error while downloading or resolving the file: {str(e)}")
        return f"Errore durante il download o la risoluzione del file M3U/M3U8: {str(e)}", 500
    except Exception as e:
        logger.info(f"General error in proxy_m3u: {str(e)}")
        return f"Errore generico durante l'elaborazione: {str(e)}", 500

@app.route('/proxy/resolve')
def proxy_resolve():
    """Resolve and return a fully inlined (rewritten) M3U8 with automatic headers.
    Eliminates the extra /proxy/m3u hop to prevent re-resolution timing issues."""
    url = unquote(request.args.get('url', '').strip())
    if not url:
        return "Errore: Parametro 'url' mancante", 400
    debug_mode = request.args.get('debug','').lower() in ('1','true','yes')

    manual_headers = {unquote(k[2:]).replace('_','-'): unquote(v).strip() for k,v in request.args.items() if k.lower().startswith('h_')}
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0+Safari/537.36",
        "Referer": "https://jxoplay.xyz/",
        "Origin": "https://jxoplay.xyz"
    }
    final_headers = {**default_headers, **manual_headers}

    try:
        result = resolve_m3u8_link(url, final_headers, debug=debug_mode)
        if not result.get('resolved_url'):
            return "Errore: Impossibile risolvere l'URL", 500

        resolved_url = result['resolved_url']
        stream_headers = {**default_headers, **result.get('headers', {})}

        # Fetch final M3U8 content directly
        r = requests.get(resolved_url, headers=stream_headers, allow_redirects=True, timeout=(10,20))
        r.raise_for_status()
        content = r.text
        final_url = r.url

        # Basic validation
        if not content.strip().startswith('#EXTM3U'):
            return "Errore: Contenuto non valido (non M3U8)", 502

        file_type = detect_m3u_type(content)
        if file_type == 'm3u':
            # Just return as-is (simple list)
            return Response(content, content_type="application/vnd.apple.mpegurl")

        # HLS: rewrite segments & keys
        parsed = urlparse(final_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/',1)[0]}/"
        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k,v in stream_headers.items()])

        rewritten = []
        for line in content.splitlines():
            l = line.strip()
            if l.startswith('#EXT-X-KEY') and 'URI="' in l:
                l = replace_key_uri(l, headers_query)
            elif l and not l.startswith('#'):
                seg_url = urljoin(base_url, l)
                l = f"/proxy/ts?url={quote(seg_url)}&{headers_query}"
            rewritten.append(l)
        rewritten_content = "\n".join(rewritten)
        return Response(rewritten_content, content_type="application/vnd.apple.mpegurl")
    except requests.RequestException as e:
        logger.info(f"proxy_resolve fetch error: {e}")
        return f"Errore durante il fetch del M3U8 finale: {e}", 500
    except Exception as e:
        logger.info(f"proxy_resolve general error: {e}")
        return f"Errore generale: {e}", 500

@app.route('/proxy/ts')
def proxy_ts():
    """Proxy per segmenti .TS con headers personalizzati - SENZA CACHE"""
    ts_url = unquote(request.args.get('url', '').strip())
    if not ts_url:
        return "Errore: Parametro 'url' mancante", 400

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        # Stream diretto senza cache per evitare freezing
        response = requests.get(ts_url, headers=headers, stream=True, allow_redirects=True, timeout=(10, 60)) # Timeout di connessione 10s, lettura 60s
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
    key_url = unquote(request.args.get('url', '').strip())
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

@app.route('/playlist/channels.m3u8', methods=['GET', 'OPTIONS'])
def playlist_channels():
    """Fixed playlist endpoint with enhanced VLC compatibility"""
    # Handle CORS preflight requests
    if request.method == 'OPTIONS':
        response_headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Range, User-Agent, Content-Type',
            'Access-Control-Max-Age': '86400'
        }
        return Response('', headers=response_headers)
    
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.info(f"Playlist request from {request.remote_addr} - User-Agent: {user_agent}")
    
    # Try local file first, then fallback to GitHub
    playlist_content = None
    local_file_path = "channel.m3u8"
    
    try:
        # First try to load from local file
        try:
            with open(local_file_path, 'r', encoding='utf-8') as f:
                playlist_content = f.read()
            logger.info("Loaded playlist from local file")
        except FileNotFoundError:
            # Fallback to GitHub
            playlist_url = "https://raw.githubusercontent.com/DeDuplicate/NewDadProxy/refs/heads/main/channel.m3u8"
            github_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
                'Accept': 'text/plain, application/vnd.apple.mpegurl, */*',
                'Cache-Control': 'no-cache'
            }
            
            response = requests.get(playlist_url, headers=github_headers, timeout=15)
            response.raise_for_status()
            playlist_content = response.text
            logger.info("Loaded playlist from GitHub")
        
        # Ensure content is properly decoded and normalized
        if isinstance(playlist_content, bytes):
            playlist_content = playlist_content.decode('utf-8')
        
        # Normalize line endings and clean up any malformed lines
        playlist_content = playlist_content.replace('\r\n', '\n').replace('\r', '\n')
        
        host_url = request.host_url.rstrip('/')
        
        modified_lines = []
        for line in playlist_content.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                # This logic will now apply to all players, including Jellyfin
                modified_lines.append(f"{host_url}/proxy/m3u?url={quote(stripped)}")
            else:
                # Keep metadata lines as they are
                modified_lines.append(line)
        
        modified_content = '\n'.join(modified_lines)
        
        # Ensure the content ends with a newline for better compatibility
        if not modified_content.endswith('\n'):
            modified_content += '\n'
        
        content_bytes = modified_content.encode('utf-8')

        
        # For VLC, ensure we return proper status and headers
        response_headers = {
            'Content-Type': 'application/x-mpegURL',
            'Content-Length': str(len(content_bytes)),
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Range, User-Agent, Content-Type',
            'Accept-Ranges': 'bytes',
        }
        return Response(content_bytes, status=200, headers=response_headers)
        
    except requests.RequestException as e:
        logger.error(f"Error loading playlist: {str(e)}")
        error_response = f"#EXTM3U\n#EXTINF:-1,Error loading playlist\n# Error: {str(e)}\n"
        return Response(error_response, status=500, headers={'Content-Type': 'application/vnd.apple.mpegurl; charset=utf-8'})
    except Exception as e:
        logger.error(f"General error: {str(e)}")
        error_response = f"#EXTM3U\n#EXTINF:-1,General error\n# Error: {str(e)}\n"
        return Response(error_response, status=500, headers={'Content-Type': 'application/vnd.apple.mpegurl; charset=utf-8'})


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
        logger.info(f"Error in /playlist/events: {str(e)}")
        return f"Interner Serverfehler: {str(e)}", 500

def fetch_schedule_data():
    """Try multiple schedule domains (daddylive.sx -> thedaddy.dad fallback)"""
    domains = [
        ("https://daddylive.sx/schedule/schedule-generated.php", "daddylive.sx", "https://daddylive.sx/"),
        ("https://thedaddy.dad/schedule/schedule-generated.php", "thedaddy.dad", "https://thedaddy.dad/")
    ]
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
    for url, host, ref in domains:
        headers = {
            "authority": host,
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-US,en;q=0.9",
            "priority": "u=1, i",
            "referer": ref,
            "sec-ch-ua": '"Not;A=Brand";v="99", "Brave";v="139", "Chromium";v="139"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "sec-gpc": "1",
            "user-agent": ua,
            "cache-control": "no-cache",
            "pragma": "no-cache"
        }
        try:
            r = requests.get(url, headers=headers, timeout=20)
            if r.status_code == 200:
                logger.info(f"Loaded schedule from {url}")
                return r.json()
            else:
                logger.info(f"Schedule fetch {url} returned {r.status_code}")
        except Exception as e:
            logger.info(f"Schedule fetch failed {url}: {e}")
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
        logger.info(f"Error processing JSON data: {e}")
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

@app.route('/discover/cdns')
def discover_cdns():
    """Discovers and tests available CDN endpoints for a given channel"""
    channel_id = request.args.get('channel_id', '1')
    test_timeout = int(request.args.get('timeout', '5'))
    
    try:
        cdn_config = get_all_player_cdns()
        working_cdns = []
        failed_cdns = []
        
        # Test newkso CDNs
        for cdn in cdn_config['newkso_cdns']:
            if 'top1.newkso.ru' in cdn:
                test_url = f"https://{cdn}/top1/cdn/premium{channel_id}/mono.m3u8"
            else:
                server_key = cdn.split('.')[0]
                if server_key.endswith('new'):
                    server_key = server_key[:-3]
                test_url = f"https://{cdn}/{server_key}/premium{channel_id}/mono.m3u8"
            
            try:
                test_headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
                    'Referer': 'https://jxoplay.xyz/premiumtv/',
                    'Origin': 'https://jxoplay.xyz'
                }
                response = requests.head(test_url, headers=test_headers, timeout=test_timeout, verify=False)
                if response.status_code in [200, 302, 206]:
                    working_cdns.append({
                        'cdn': cdn,
                        'url': test_url,
                        'status': response.status_code
                    })
                    logger.info(f"Working CDN found: {test_url}")
                else:
                    failed_cdns.append({
                        'cdn': cdn,
                        'url': test_url,
                        'status': response.status_code
                    })
            except Exception as e:
                failed_cdns.append({
                    'cdn': cdn,
                    'url': test_url,
                    'error': str(e)
                })
        
        result = {
            'channel_id': channel_id,
            'working_cdns': working_cdns,
            'failed_cdns': failed_cdns,
            'total_tested': len(cdn_config['newkso_cdns']),
            'working_count': len(working_cdns),
            'failed_count': len(failed_cdns)
        }
        
        return Response(json.dumps(result, indent=2), content_type='application/json')
        
    except Exception as e:
        logger.error(f"CDN discovery error: {str(e)}")
        return f"CDN discovery error: {str(e)}", 500

@app.route('/list/cdns')
def list_cdns():
    """Returns all known CDN configurations"""
    try:
        cdn_config = get_all_player_cdns()
        return Response(json.dumps(cdn_config, indent=2), content_type='application/json')
    except Exception as e:
        return f"Error listing CDNs: {str(e)}", 500

@app.route('/test/connectivity')
def test_connectivity():
    """Test basic connectivity to CDN servers"""
    try:
        cdn_tests = []
        test_domains = [
            'zekonew.newkso.ru',
            'nfsnew.newkso.ru', 
            'windnew.newkso.ru',
            'ddy1new.newkso.ru',
            'top1.newkso.ru'
        ]
        
        for domain in test_domains:
            try:
                test_url = f"https://{domain}/"
                response = requests.head(test_url, timeout=5, verify=False)
                cdn_tests.append({
                    'domain': domain,
                    'status': response.status_code,
                    'reachable': True
                })
            except Exception as e:
                cdn_tests.append({
                    'domain': domain,
                    'error': str(e),
                    'reachable': False
                })
        
        return Response(json.dumps({'tests': cdn_tests}, indent=2), content_type='application/json')
        
    except Exception as e:
        return f"Connectivity test error: {str(e)}", 500

@app.route('/test/bypass')
def test_bypass():
    """Test IP bypass strategies for authentication"""
    channel_id = request.args.get('channel_id', '141')
    
    try:
        # Test different auth servers with various header strategies
        auth_servers = [
            'https://top2new.newkso.ru/auth.php',
            'https://top1new.newkso.ru/auth.php', 
            'https://windnew.newkso.ru/auth.php',
            'https://nfsnew.newkso.ru/auth.php'
        ]
        
        header_strategies = [
            {
                'name': 'mobile_safari',
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Referer': 'https://jxoplay.xyz/premiumtv/'
                }
            },
            {
                'name': 'desktop_chrome',
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
                    'Accept': 'application/json, text/plain, */*',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Referer': 'https://jxoplay.xyz/'
                }
            }
        ]
        
        results = []
        
        for server in auth_servers:
            for strategy in header_strategies:
                test_url = f"{server}?channel_id=premium{channel_id}&ts=1754836000&rnd=test1234&sig=dummysig"
                try:
                    response = requests.head(test_url, headers=strategy['headers'], timeout=5, verify=False)
                    results.append({
                        'server': server,
                        'strategy': strategy['name'],
                        'status': response.status_code,
                        'success': response.status_code not in [403, 404]
                    })
                except Exception as e:
                    results.append({
                        'server': server,
                        'strategy': strategy['name'],
                        'error': str(e),
                        'success': False
                    })
        
        return Response(json.dumps({'channel_id': channel_id, 'tests': results}, indent=2), content_type='application/json')
        
    except Exception as e:
        return f"Bypass test error: {str(e)}", 500

@app.route('/')
def index():
    """Pagina principale che mostra un messaggio di benvenuto"""
    logger.info(f"Main page access from {request.remote_addr} - User-Agent: {request.headers.get('User-Agent', 'Unknown')}")
    return "Proxy started!"

if __name__ == '__main__':
    logger.info("Proxy started!")
    app.run(host="0.0.0.0", port=7860, debug=False)
