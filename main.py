# -*- coding: utf-8 -*-
"""
Autel Forensics Analyzer PRO (AFAP)

Version: 1.1 Beta
Auteur: Vincent Chapeau
Contact : vincent.chapeau@teeltechcanada.com
Date: 31 juillet 2025

Description:
Outil d'analyse forensique pour les tablettes Autel. (MaxiIM KM100 : OK)
Extrait les VINs, les logs d'activité, les adresses MAC, etc., depuis
un dossier ou une archive (.zip, .7z). 
L'import depuis une extraction physique fera l'objet d'une mise à jour ainsi que le support d'autres modèles Autel.
"""

# main.py

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
import datetime
import logging
import zipfile
import py7zr
import tempfile
import shutil

# --- Imports des modules d'extraction ---
from utils import setup_logging, get_tablet_info, export_tablet_info_csv
from extract_vins import extract_all_vins
from extract_log_events import extract_all_log_events
from extract_mac import extract_mac
from extract_user_and_endpoints import extract_user_and_endpoints
from extract_passwords import extract_passwords
from extract_vehicle_refs import extract_vehicle_refs
from extract_dcim_media import extract_dcim_media
from export_sqlite_tables import export_sqlite_tables

# ==================================================================
# Texte de la fiche explicative (Lisez-moi)
# ==================================================================
README_TEXT = """
Fiche Explicative des Fichiers de Rapport - Analyse Tablette Autel
Version: 1.0

Ce document décrit le contenu de chaque fichier CSV généré par l'outil d'analyse forensique AFAP.
Chaque fichier a pour but d'isoler un type d'information spécifique afin de faciliter l'enquête.

---------------------------------
1. INFORMATIONS GÉNÉRALES
---------------------------------

- rapport_analyse.txt
  Contenu : Un résumé général de toute l'extraction (informations tablette, comptes de chaque catégorie, liste des fichiers exportés).
  Utilité : Donne une vue d'ensemble rapide de l'analyse.

- tablet_info.csv
  Contenu : Les détails d'identification de la tablette (N/S, modèle, langue, fuseau horaire).
  Utilité : Permet d'identifier formellement l'appareil source des données.

---------------------------------
2. DONNÉES LIÉES AUX VÉHICULES
---------------------------------

- vins_extraits.csv
  Contenu : Liste tous les Numéros d'Identification de Véhicule (VIN) trouvés.
  Utilité : Preuve directe des véhicules spécifiques sur lesquels la tablette a pu être utilisée. La colonne 'statut_validation' indique la conformité du VIN à la norme.

- vehicule_refs_found.csv
  Contenu : Une liste nettoyée de références à des véhicules (Marque, Modèle, Années) et à des pièces (OEM, FCCID) extraites des logs.
  Utilité : Donne un contexte sur les types de véhicules ciblés, même sans VIN.

- masdas.db_tb_history_menu.csv (et autres exports de BDD)
  Contenu : Export direct de la base de données interne. La table 'tb_history_menu' contient un journal structuré de chaque session de diagnostic (quel véhicule, quelle fonction, à quelle heure).
  Utilité : Fournit un historique d'activité fiable et horodaté, souvent plus complet que les logs.

---------------------------------
3. DONNÉES DE CONNECTIVITÉ ET D'ENVIRONNEMENT
---------------------------------

- mac_found.csv
  Contenu : Liste de toutes les adresses MAC (identifiants d'appareils réseau) vues par la tablette (VCI, Wi-Fi, Bluetooth...).
  Utilité : Identifie les appareils dans l'environnement de la tablette. La colonne 'randomized' indique si l'adresse est probablement privée/aléatoire.

- mac_connections_found.csv
  Contenu : Journal des événements de connexion et déconnexion associés aux adresses MAC.
  Utilité : Aide à construire une chronologie des interactions réseau.

- endpoints_found.csv
  Contenu : Liste toutes les adresses internet (URL) avec lesquelles la tablette a communiqué.
  Utilité : Peut révéler des communications avec des serveurs de mise à jour, des services cloud, ou d'autres sites.

---------------------------------
4. DONNÉES UTILISATEUR
---------------------------------

- userId_found.csv
  Contenu : Identifiants de comptes utilisateurs Autel trouvés dans les logs.
  Utilité : Permet d'identifier le ou les comptes connectés à la tablette.

- pwd_sn_found.csv
  Contenu : Paires de numéros de série et de mots de passe trouvées en clair dans certains logs.
  Utilité : Identifiants de connexion critiques.

---------------------------------
5. DONNÉES D'ACTIVITÉ BRUTES
---------------------------------

- log_events_found.csv
  Contenu : Fichier le plus détaillé, contenant toutes les lignes jugées pertinentes extraites des fichiers de log, classées par type d'événement.
  Utilité : Base pour une analyse en profondeur. Contient les détails de chaque action, les appareils Bluetooth détectés, les réseaux Wi-Fi vus, les erreurs, etc.
"""


class AutelApp(tk.Tk):
    # ==================================================================
    # 1. INITIALISATION DE L'INTERFACE
    # ==================================================================
    def __init__(self):
        super().__init__()
        self.title("Autel Forensics Analyzer PRO")
        self.geometry("560x500")
        self.resizable(False, False)
        
        self.start_time = None
        self.analysis_is_running = False
        self.progress_message = tk.StringVar(value="En attente...")
        self.progress_percentage = tk.DoubleVar(value=0.0)
        self.time_message = tk.StringVar(value="")

        # --- Création des widgets ---
        frm_model = ttk.LabelFrame(self, text='Modèle')
        frm_model.pack(fill='x', padx=10, pady=3)
        self.model_var = tk.StringVar(value='KM100')
        ttk.Radiobutton(frm_model, text='MaxiIM KM100', variable=self.model_var, value='KM100').pack(side='left', padx=7)
        
        frm_src = ttk.LabelFrame(self, text='Source (Dossier ou Archive .zip/.7z)')
        frm_src.pack(fill='x', padx=10, pady=3)
        self.source_path = tk.StringVar()
        ttk.Entry(frm_src, textvariable=self.source_path).pack(side='left', fill='x', expand=True, padx=5, pady=2)
        ttk.Button(frm_src, text='Parcourir', command=self.select_source).pack(side='right', padx=(0, 5))
        
        frm_dst = ttk.LabelFrame(self, text='Export')
        frm_dst.pack(fill='x', padx=10, pady=3)
        self.dest_path = tk.StringVar()
        ttk.Entry(frm_dst, textvariable=self.dest_path).pack(side='left', fill='x', expand=True, padx=5, pady=2)
        ttk.Button(frm_dst, text='Parcourir', command=self.select_dest).pack(side='right', padx=(0, 5))
        
        self.progress = ttk.Progressbar(self, orient='horizontal', length=520, mode='determinate', variable=self.progress_percentage)
        self.progress.pack(padx=10, pady=6)
        
        ttk.Label(self, textvariable=self.progress_message).pack()
        ttk.Label(self, textvariable=self.time_message).pack()
        
        self.btn_start = ttk.Button(self, text='Analyser', width=18, command=self.start_analysis)
        self.btn_start.pack(pady=10)
        
        tk.Label(self, text="AFAP v1.1 Beta | Créé par Vincent Chapeau - 2025.08.04", font=("Arial", 9), fg="black").place(relx=1.0, rely=1.0, anchor='se')

    # ==================================================================
    # 2. FONCTIONS DE GESTION DE L'INTERFACE
    # ==================================================================
    def select_source(self):
        is_file = messagebox.askyesno(
            "Sélection de la source",
            "Voulez-vous sélectionner un fichier archive (.zip, .7z) ?\n\n"
            "(Cliquez sur 'Non' pour sélectionner un dossier)"
        )
        if is_file:
            path = filedialog.askopenfilename(
                title="Sélectionner une archive",
                filetypes=[("Archives", "*.zip *.7z"), ("Tous les fichiers", "*.*")]
            )
        else:
            path = filedialog.askdirectory(title="Sélectionner un dossier")
        if path:
            self.source_path.set(path)

    def select_dest(self):
        path = filedialog.askdirectory()
        if path: self.dest_path.set(path)

    def _update_ui_loop(self, step=0):
        if self.analysis_is_running:
            elapsed = datetime.datetime.now() - self.start_time
            elapsed_str = str(elapsed).split('.')[0]
            start_str = self.start_time.strftime('%H:%M:%S')
            chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            spinner = chars[step]
            self.time_message.set(f"Lancé à {start_str} | Durée: {elapsed_str} | {spinner}")
            next_step = (step + 1) % len(chars)
            self.after(100, self._update_ui_loop, next_step)
        else:
            if self.start_time:
                final_elapsed = datetime.datetime.now() - self.start_time
                final_duration = str(final_elapsed).split('.')[0]
                self.time_message.set(f"Analyse terminée en {final_duration}")
    
    def _show_final_summary(self, summary):
        self.analysis_is_running = False
        self._update_ui_loop()
        messagebox.showinfo("Résumé de l'Analyse", summary)
        self.btn_start.config(text='Fermer', command=self.quit, state='normal')

    # ==================================================================
    # 3. DÉMARRAGE DE L'ANALYSE
    # ==================================================================
    def start_analysis(self):
        source_path = self.source_path.get()
        if not source_path or not self.dest_path.get():
            messagebox.showerror("Erreur", "Veuillez sélectionner une source et un dossier d'export.")
            return
        
        if not os.path.exists(source_path):
            messagebox.showerror("Erreur", f"Le chemin source n'existe pas :\n{source_path}")
            return
            
        self.btn_start.config(text='Analyse en cours...', state='disabled')
        self.start_time = datetime.datetime.now()
        
        self.analysis_is_running = True
        self._update_ui_loop()
        
        threading.Thread(target=self.run_analysis, daemon=True).start()

    # ==================================================================
    # 4. CŒUR DE L'ANALYSE (THREAD SÉPARÉ)
    # ==================================================================
    def run_analysis(self):
        src_path = self.source_path.get()
        dst = self.dest_path.get()
        
        temp_dir = None
        source_to_scan = src_path

        try:
            # --- Étape 1 : Décompression si la source est une archive ---
            if os.path.isfile(src_path):
                self.progress.config(mode='indeterminate')
                self.progress.start()
                
                if src_path.lower().endswith('.zip'):
                    self.progress_message.set("Décompression .zip (avec préservation des dates)...")
                    temp_dir = tempfile.mkdtemp(prefix="afap_")
                    with zipfile.ZipFile(src_path, 'r') as zip_ref:
                        for member in zip_ref.infolist():
                            extracted_path = zip_ref.extract(member, temp_dir)
                            if not member.is_dir():
                                date_time = datetime.datetime(*member.date_time)
                                timestamp = date_time.timestamp()
                                os.utime(extracted_path, (timestamp, timestamp))
                    source_to_scan = temp_dir
                elif src_path.lower().endswith('.7z'):
                    self.progress_message.set("Décompression de l'archive .7z...")
                    temp_dir = tempfile.mkdtemp(prefix="afap_")
                    with py7zr.SevenZipFile(src_path, mode='r') as z:
                        z.extractall(path=temp_dir)
                    source_to_scan = temp_dir
                
                self.progress.stop()
                self.progress.config(mode='determinate')

            # --- Étape 2 : Initialisation et Préparation ---
            self.progress_message.set("Initialisation...")
            self.progress_percentage.set(0)
            setup_logging(dst)
            
            self.progress.config(mode='indeterminate')
            self.progress.start()
            self.progress_message.set("Scan initial des fichiers...")
            tablet_info = get_tablet_info(source_to_scan)
            self.progress.stop()
            self.progress.config(mode='determinate')

            # --- Étape 3 : Création du dossier d'export ---
            self.progress_message.set("Préparation de l'export...")
            self.progress_percentage.set(5)
            serial = tablet_info.get('serial', 'inconnu')
            export_dir = os.path.join(dst, f"Analyse_{serial}_{self.start_time.strftime('%Y%m%d_%H%M%S')}")
            os.makedirs(export_dir, exist_ok=True)
            export_tablet_info_csv(export_dir, tablet_info)

            # --- Étape 4 : Chargement de la skiplist MD5 ---
            self.progress_message.set("Chargement de la liste d'exclusion MD5...")
            self.progress_percentage.set(10)
            script_dir = os.path.dirname(os.path.abspath(__file__))
            skiplist_file = os.path.join(script_dir, 'hash_skiplist.txt')
            skip_md5 = {line.strip().lower() for line in open(skiplist_file, 'r', encoding='utf-8') if line.strip()} if os.path.isfile(skiplist_file) else set()

            # --- Étape 5 : Définition et Exécution des Modules ---
            modules_to_run = [
                ("Extraction des VINs", extract_all_vins), ("Extraction des événements de logs", extract_all_log_events),
                ("Extraction des adresses MAC", extract_mac), ("Extraction des utilisateurs et URLs", extract_user_and_endpoints),
                ("Extraction des mots de passe", extract_passwords), ("Extraction des références véhicule", extract_vehicle_refs),
                ("Copie des médias DCIM", extract_dcim_media),
                ("Export des tables SQLite", export_sqlite_tables) 
            ]
            results = {}
            total_modules = len(modules_to_run)
            base_progress = 15.0

            for i, (name, func) in enumerate(modules_to_run, 1):
                module_weight = 80.0 / total_modules
                def module_progress_callback(current, total):
                    if total > 0:
                        module_progress = (current / total) * module_weight
                        self.progress_percentage.set(base_progress + module_progress)
                        self.progress_message.set(f"Module ({i}/{total_modules}): {name} ({current}/{total})")
                try:
                    args = {"src_dir": source_to_scan, "export_dir": export_dir, "skip_md5": skip_md5, "progress_callback": module_progress_callback}
                    if name == "Export des tables SQLite":
                        args["tables"] = ['tb_history_menu', 'tb_user_info', 'tb_vci_record']
                    result = func(**args)
                    results[name] = len(result) if result is not None else 0
                except Exception as e:
                    logging.exception(f"ERREUR CRITIQUE dans le module {name}")
                    results[name] = "Erreur"
                base_progress += module_weight

            # --- Étape 6 : Génération des Rapports ---
            self.progress_message.set("Génération des rapports...")
            self.progress_percentage.set(98)
            report_path = os.path.join(export_dir, 'rapport_analyse.txt')
            with open(report_path, 'w', encoding='utf-8') as rpt:
                rpt.write(f"Rapport d'analyse AUTEL - {datetime.datetime.now().strftime('%Y%m%d %H%M%S')}\n" + "="*40 + "\n\n")
                rpt.write(f"Dossier source : {src_path}\n" + f"Dossier d'export : {export_dir}\n\n")
                rpt.write("--- Informations Tablette ---\n")
                for key, value in tablet_info.items(): rpt.write(f"{key.capitalize()}: {value}\n")
                rpt.write("\n" + "--- Résumé des Extractions ---\n")
                for name, count in results.items(): rpt.write(f"{name}: {count}\n")
                rpt.write("\n" + "--- Fichiers exportés ---\n")
                for fname in sorted(os.listdir(export_dir)): rpt.write(f"  - {fname}\n")
            
            readme_path = os.path.join(export_dir, 'LISEZMOI_Description_des_fichiers.txt')
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(README_TEXT)

            # --- Étape 7 : Affichage du Résumé et Fin ---
            self.progress_message.set("Analyse terminée !")
            self.progress_percentage.set(100)
            
            unit_labels = { "Extraction des VINs": "VINs", "Extraction des événements de logs": "événements", "Extraction des adresses MAC": "adresses/événements", "Extraction des utilisateurs et URLs": "éléments", "Extraction des mots de passe": "mots de passe", "Extraction des références véhicule": "références", "Copie des médias DCIM": "fichiers", "Export des tables SQLite": "tables" }
            summary = f"Analyse terminée avec succès !\n\nExport dans : {os.path.basename(export_dir)}\n--------------------------------------\n"
            for name, count in results.items():
                unit = unit_labels.get(name, "éléments")
                summary += f"- {name}: {count} {unit if isinstance(count, int) else ''} trouvés\n" if isinstance(count, int) else f"- {name}: {count}\n"
            summary += "--------------------------------------\nConsultez 'rapport_analyse.txt' et 'LISEZMOI' pour les détails."
            
            self.after(0, self._show_final_summary, summary)

        except Exception as e:
            logging.exception("Une erreur fatale est survenue durant l'analyse.")
            self.progress_message.set("Erreur Fatale !")
            messagebox.showerror("Erreur Fatale", f"L'analyse a échoué.\n\nErreur: {e}\n\nConsultez le log.")
            self.btn_start.config(text='Analyser', state='normal')
        
        finally:
            if temp_dir:
                try:
                    self.progress_message.set("Nettoyage des fichiers temporaires...")
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logging.error(f"Erreur lors du nettoyage du dossier temporaire {temp_dir}: {e}")
            self.analysis_is_running = False

# ==================================================================
# 5. POINT D'ENTRÉE DE L'APPLICATION
# ==================================================================
if __name__ == '__main__':
    app = AutelApp()
    app.mainloop()

