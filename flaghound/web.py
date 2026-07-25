"""
Web Module for FlagHound v2.0
Fetches and analyzes URLs without manual download.
"""
import urllib.request
import urllib.error
import ssl
from pathlib import Path

# Default timeout for requests
DEFAULT_TIMEOUT = 30

# Maximum response size to download (10 MB)
MAX_RESPONSE_SIZE = 10 * 1024 * 1024

def fetch_url(url, timeout=DEFAULT_TIMEOUT):
    """
    Fetch content from URL safely.
    Returns dict with 'content' (bytes) or 'error' message.
    """
    result = {}
    
    if not url.startswith(('http://', 'https://')):
        return {'error': 'Invalid URL scheme'}
    
    # Create SSL context that doesn't verify certificates (for CTF use)
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    except Exception:
        ssl_context = None
    
    # Set up request with headers to look like a browser
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'identity',  # Don't accept compression to simplify handling
    }
    
    try:
        req = urllib.request.Request(url, headers=headers)
        
        if ssl_context:
            response = urllib.request.urlopen(req, context=ssl_context, timeout=timeout)
        else:
            response = urllib.request.urlopen(req, timeout=timeout)
        
        # Check content length if available
        content_length = response.headers.get('Content-Length')
        if content_length and int(content_length) > MAX_RESPONSE_SIZE:
            return {'error': f'Response too large: {content_length} bytes'}
        
        # Read with size limit
        content = b''
        remaining = MAX_RESPONSE_SIZE
        
        while True:
            chunk = response.read(8192)
            if not chunk:
                break
            
            if len(chunk) > remaining:
                content += chunk[:remaining]
                result['warning'] = 'Response truncated due to size limit'
                break
            
            content += chunk
            remaining -= len(chunk)
        
        result['content'] = content
        result['url'] = url
        result['status'] = response.status
        result['headers'] = dict(response.headers)
        
        # Determine filename from URL or Content-Disposition
        content_disposition = response.headers.get('Content-Disposition', '')
        if 'filename=' in content_disposition:
            # Extract filename from Content-Disposition
            for part in content_disposition.split(';'):
                if 'filename=' in part:
                    filename = part.split('=')[1].strip('"\'')
                    result['filename'] = filename
                    break
        
        if 'filename' not in result:
            # Use last part of URL path
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path
            result['filename'] = Path(path).name if path else 'downloaded_file'
        
    except urllib.error.HTTPError as e:
        result['error'] = f'HTTP Error {e.code}: {e.reason}'
    except urllib.error.URLError as e:
        result['error'] = f'URL Error: {e.reason}'
    except TimeoutError:
        result['error'] = 'Request timed out'
    except Exception as e:
        result['error'] = f'Failed to fetch URL: {str(e)}'
    
    return result

def is_url(target):
    """Check if target string is a URL."""
    return target.startswith(('http://', 'https://'))

def get_url_content_type(headers):
    """Extract content type from response headers."""
    content_type = headers.get('Content-Type', '')
    return content_type.split(';')[0].strip()
