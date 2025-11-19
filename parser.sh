#!/bin/sh

# Gewünschte DetectorType-Werte
desired_detector_types=(2 3 7 9 15 17 18 31 39 40 48 69 71 120 177 350 353 582 584 599 737 924)

# Zu parsende JSON-Datei
input_file="trufflehog.json"
output_file="filtered_data.json"

# Überprüfe, ob die Eingabedatei existiert
if [[ ! -f "$input_file" ]]; then
  echo "Die Datei $input_file wurde nicht gefunden."
  exit 1
fi

# Filterfunktion, um den DetectorType zu überprüfen
# jq: JSON-Parsing-Tool; Muss installiert sein!
filter_json() {
  jq --argjson desired_types "$(printf '%s\n' "${desired_detector_types[@]}" | jq -s '.')" '
    . | select(.DetectorType as $d | $desired_types | index($d) != null) |
    {
      SourceMetadata: .SourceMetadata,
      DetectorName: .DetectorName,
      DetectorType: .DetectorType,
      Raw: .Raw
    }
  '
}

# JSON-Datei zeilenweise einlesen, formatieren und filtern
while IFS= read -r line; do
  echo "$line" | filter_json
done < "$input_file" | jq -s . > "$output_file"

# Ausgabeerfolgsmeldung
echo "Die gefilterten Daten wurden erfolgreich in '$output_file' gespeichert."
