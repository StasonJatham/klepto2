import json
import os
#print(os.getenv('UNDESIRED_TERMS')) 
# Umgebungsvariablen einlesen
#desired_detector_type = json.loads(os.getenv('DETECTOR_TYPES', '[]')) #gesuchten Detector Types
#undesired_terms = json.loads(os.getenv('UNDESIRED_TERMS')) #Liste von unerwünschten Begriffen für das "Raw"-Feld
#input_file = os.getenv('INPUT_FILE', 'trufflehog.json') #Zu parsende JSON-Datei
#output_file = os.getenv('OUTPUT_FILE', 'filtered_data.json') #Ergebnis File

desired_detector_type = [2, 3, 7, 9, 15, 17, 18, 31, 39, 40, 48, 69, 71, 120, 177, 350, 353, 582, 584, 599, 737, 924]
undesired_terms = ["example", "test", "dummy", "sample"]
input_file = 'trufflehog.json'
output_file = 'filtered_data.json'

def contains_undesired_term(raw_value, terms):
    """Überprüft, ob der Raw-Wert unerwünschte Begriffe enthält."""
    if raw_value:
        return any(term in raw_value.lower() for term in terms)
    return False

try:
    # Öffne die JSON-Datei und lade den Inhalt
    with open(input_file, 'r') as json_file:
        # JSON-Datei nicht korrekt formatiert, daher lines einlesen
        lines = json_file.readlines()

        # Formatiere die Daten zu einer Liste von JSON-Objekten
        formatted_data = [json.loads(line) for line in lines if line.strip()]

        # Filtere Objekte basierend auf den gewünschten DetectorType und unerwünschte Begriffe im Raw-Feld
        filtered_data = [
            {
                'SourceMetadata': obj.get('SourceMetadata'),
                'DetectorName': obj.get('DetectorName'),
                'DetectorType': obj.get('DetectorType'),
                'Raw': obj.get('Raw')
            }
            for obj in formatted_data
            if obj.get('DetectorType') in desired_detector_type and not contains_undesired_term(obj.get('Raw'), undesired_terms)
        ]

    # Speichere die gefilterten Daten in einer neuen JSON-Datei
    with open(output_file, 'w') as output_file:
        json.dump(filtered_data, output_file, indent=4)

    print(f"Die gefilterten Daten wurden erfolgreich in {output_file.name} gespeichert.")

except FileNotFoundError:
    print(f"Die Datei '{input_file}' wurde nicht gefunden.")
except json.JSONDecodeError as e:
    print(f"Fehler beim Verarbeiten der JSON-Datei: {e}")
except Exception as e:
    print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")
