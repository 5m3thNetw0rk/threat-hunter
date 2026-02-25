import json
import urllib.request
import os

def get_geo_coords(ip):
    """Fetches latitude and longitude for a given IP."""
    try:
        url = f"http://ip-api.com/json/{ip}"
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            if data['status'] == 'success':
                return {
                    "lat": data['lat'],
                    "lon": data['lon'],
                    "city": data['city'],
                    "country": data['country']
                }
    except:
        return None

def generate_html_map(threat_list):
    """
    Creates a simple HTML map using Leaflet.js via a template.
    We use a single HTML file approach to keep it portable.
    """
    markers = ""
    for threat in threat_list:
        geo = get_geo_coords(threat['ip'])
        if geo:
            markers += f"L.marker([{geo['lat']}, {geo['lon']}]).addTo(map).bindPopup('<b>Threat IP:</b> {threat['ip']}<br><b>Location:</b> {geo['city']}, {geo['country']}');\n"

    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Threat Map</title>
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
        <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
        <style>#map {{ height: 600px; width: 100%; }} body {{ font-family: sans-serif; }}</style>
    </head>
    <body>
        <h1>🌐 Adversary Origin Map</h1>
        <div id="map"></div>
        <script>
            var map = L.map('map').setView([20, 0], 2);
            L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png').addTo(map);
            {markers}
        </script>
    </body>
    </html>
    """
    
    with open("threat_map.html", "w") as f:
        f.write(html_template)
    print("[+] Success: threat_map.html generated. Open it in a browser to see attack origins.")

if __name__ == "__main__":
    # Example list - in production, this pulls from your detected_threats.json
    threats = [
        {"ip": "1.1.1.1"}, # Example Cloudflare (AU)
        {"ip": "8.8.8.8"}, # Example Google (US)
        {"ip": "185.220.101.42"} # Example Tor Exit Node (DE)
    ]
    generate_html_map(threats)
