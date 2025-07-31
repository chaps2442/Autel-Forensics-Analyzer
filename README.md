# Autel-Forensics-Analyzer
Outil d'analyse forensique pour extractions de tablettes Autel.

Fonctionnalités Principales
L'outil est conçu pour analyser une extraction de tablette Autel, qu'elle soit sous forme de dossier, d'archive .zip ou .7z. Il automatise la recherche et l'extraction d'une grande variété d'artefacts forensiques pour reconstituer l'activité de l'utilisateur.

Données de Connectivité et d'Environnement
Adresses MAC : Le script identifie toutes les adresses MAC uniques (Wi-Fi et Bluetooth) vues par la tablette. Pour chacune, il détermine le constructeur, indique si elle est probablement aléatoire, et génère un rapport séparé pour les dates et heures de connexion et déconnexion.

Appareils Bluetooth : Il liste les noms de tous les appareils Bluetooth détectés à proximité (téléphones, TV, autres véhicules, etc.).

Réseaux Wi-Fi : Il extrait les noms (SSID) des réseaux Wi-Fi qui ont été vus par la tablette.

Données d'Activité et Véhicules
Numéros de Châssis (VIN) : L'outil scanne tous les fichiers, y compris les fichiers binaires (.bin) et les logs, pour trouver tous les VINs potentiels. Chaque VIN est validé pour s'assurer qu'il provient d'un constructeur connu.

Historique des Véhicules : Il se connecte à la base de données interne de la tablette (masdas.db) pour extraire l'historique des diagnostics : quel véhicule (marque, modèle), quelle fonction a été utilisée, et à quel moment.

Actions Utilisateur : Il analyse en profondeur les logs pour extraire une chronologie détaillée des actions de l'utilisateur, comme les fonctions de programmation de clés utilisées, les résultats ("succès", "échec"), ou les erreurs rencontrées.

Comptes et Mots de Passe : Le script recherche et extrait les comptes utilisateurs Autel ainsi que les paires de numéro de série/mot de passe trouvées en clair dans les logs.

Formats de Source et Rapports
L'outil prend en charge une source de données flexible et génère un ensemble de rapports clairs :

Source : Un dossier contenant les fichiers, ou une archive .zip / .7z.

Rapports : Il produit une série de fichiers CSV faciles à analyser, un rapport de synthèse (rapport_analyse.txt), ainsi qu'une fiche explicative (LISEZMOI.txt)
