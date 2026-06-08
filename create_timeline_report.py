# create_timeline_report.py
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
import os, csv, logging
from datetime import datetime

def create_timeline_report(src_dir, export_dir, **kwargs):
    timeline_events = []
    
    files_to_parse = [
        ('mac_connections_found.csv', 'date_evenement', '%Y-%m-%d %H:%M:%S', 'Connexion Réseau', ['event', 'mac', 'vendor']),
        ('vins_extraits.csv', 'date_modification', '%Y-%m-%d %H:%M:%S', 'VIN Trouvé', ['vin', 'statut_validation']),
    ]
    
    for filename, date_col, date_format, category, detail_cols in files_to_parse:
        path = os.path.join(export_dir, filename)
        if not os.path.isfile(path): continue
        
        with open(path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    timestamp_str = row.get(date_col, '')[:19]
                    if not timestamp_str: continue
                    timestamp = datetime.strptime(timestamp_str, date_format)
                    details = f"{category}: " + ", ".join(f"{col}={row.get(col, '')}" for col in detail_cols)
                    timeline_events.append({"timestamp": timestamp, "source_file": filename, "details": details})
                except (ValueError, TypeError): continue
    
    timeline_events.sort(key=lambda x: x['timestamp'])
    
    html_path = os.path.join(export_dir, 'Timeline_Chronologique.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write("<html><head><title>Timeline Chronologique</title>")
        f.write("<style>body{font-family:sans-serif;} table{border-collapse:collapse; width:100%;} th,td{border:1px solid #ddd; padding:8px; text-align:left;} tr:nth-child(even){background-color:#f2f2f2;} th{background-color:#4CAF50; color:white;}</style>")
        f.write("</head><body><h1>Timeline Chronologique des Événements</h1><table>")
        f.write("<tr><th>Date et Heure</th><th>Source du Fichier</th><th>Détails de l'Événement</th></tr>")
        for event in timeline_events:
            ts = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"<tr><td>{ts}</td><td>{event['source_file']}</td><td>{event['details']}</td></tr>")
        f.write("</table></body></html>")
        
    return timeline_events
