# -*- coding: utf-8 -*-
"""
Autel Forensics Analyzer PRO (AFAP)

Version: 2.1.0 (refonte unifiée — VFS + modules étendus + rapport forensique)
Auteur: Vincent Chapeau
Contact : vincent.chapeau@teeltechcanada.com
Date: 2026-05-11

Description:
Outil d'analyse forensique pour tablettes Autel (KM100, KM100X, …).
Analyse les dossiers ou lit directement dans les archives (ZIP/7z) via
une architecture VFS unifiée.

Modules historiques préservés (VINs / MAC / mots de passe / userId / endpoints /
références véhicule / DCIM / tables SQLite / timeline HTML).

Modules ajoutés en v2.0.0 :
  - extract_cloud_e_data       : opérations véhicule documentées (Scan/CloudEData/*.json)
  - extract_module_usage       : usage par marque (.FREQUENCY × CARBASE_INFO × AllUpdateList)
  - extract_vci_logs           : journaux VCI (Scan/Data/.VciLog/*.log)
  - extract_es_history         : ES File Explorer (visit_history + appinfo.db)
  - extract_external_storage   : SD/USB montées (UUID FAT/exFAT)
  - extract_secrets            : PEM, certificats, licence Scan, rdp_client.ini, JPush
  - extract_event_log          : chronologie Scan/EventLog/<epoch_ms>
  - create_forensic_report     : rapport_forensique.md consolidé
"""
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
import datetime
import logging
import webbrowser

# --- Dépendances Optionnelles ---
try:
    import py7zr
    PY7ZR_AVAILABLE = True
except ImportError:
    PY7ZR_AVAILABLE = False
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# --- Imports des modules historiques ---
from utils import setup_logging, get_tablet_info, export_tablet_info_csv
from core_scanner import should_skip
from extract_vins import extract_all_vins
from extract_log_events import extract_all_log_events
from extract_mac import extract_mac
from extract_user_and_endpoints import extract_user_and_endpoints
from extract_passwords import extract_passwords
from extract_vehicle_refs import extract_vehicle_refs
from extract_dcim_media import extract_dcim_media
from export_sqlite_tables import export_sqlite_tables
from create_timeline_report import create_timeline_report

# --- Imports modules v2.0.0 ---
from extract_cloud_e_data import extract_cloud_e_data
from extract_module_usage import extract_module_usage
from extract_vci_logs import extract_vci_logs
from extract_es_history import extract_es_history
from extract_external_storage import extract_external_storage
from extract_secrets import extract_secrets
from extract_event_log import extract_event_log
from extract_wal_indicators import extract_wal_indicators
from create_forensic_report import create_forensic_report
# --- v2.2/2.3 ---
from extract_account import extract_account
from extract_wifi import extract_wifi
from extract_bluetooth import extract_bluetooth
from extract_kyc_qr import extract_kyc_qr
from parse_uart_bootlog import parse_uart_bootlog, detect_tablet_time
from create_master_timeline import create_master_timeline
from create_timeline_html import create_timeline_html
from clock_offset import ClockOffset
from finalize_export import finalize_export
from i18n import set_lang as _set_lang, get_lang as _get_lang

# ==================================================================
# Fonctions Utilitaires
# ==================================================================
def human_bytes(n):
    if n is None: n = 0
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024.0: return f"{n:3.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"

def read_readme_text(script_dir):
    for filename in ["readme.md", "LISEZMOI.txt", "README.txt"]:
        path = os.path.join(script_dir, filename)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f: return f.read()
            except Exception: continue
    return "Fichier d\'aide (readme.md) non trouvé."

# ==================================================================
# Classe principale de l\'Application
# ==================================================================
class AutelApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Autel Forensics Analyzer PRO v2.1.0")
        self.geometry("700x520")
        self.resizable(False, False)

        self.start_time = None
        self.analysis_is_running = False
        self.last_export_dir = None
        self.progress_message = tk.StringVar(value="En attente…")
        self.progress_percentage = tk.DoubleVar(value=0.0)
        self.time_message = tk.StringVar(value="")
        self.res_message = tk.StringVar(value="")
        self.dep_py7zr = tk.StringVar()
        self.dep_psutil = tk.StringVar()

        self._build_ui()
        self._check_dependencies()

    def _build_ui(self):
        frm_src = ttk.LabelFrame(self, text='Source de Données (Dossier ou Archive .zip/.7z)')
        frm_src.pack(fill='x', padx=10, pady=(10, 5))
        self.source_path = tk.StringVar()
        ttk.Entry(frm_src, textvariable=self.source_path).pack(side='left', fill='x', expand=True, padx=5, pady=2)
        ttk.Button(frm_src, text='Parcourir...', command=self.select_source).pack(side='right', padx=(0, 5))
        
        frm_dst = ttk.LabelFrame(self, text='Export')
        frm_dst.pack(fill='x', padx=10, pady=5)
        self.dest_path = tk.StringVar()
        ttk.Entry(frm_dst, textvariable=self.dest_path).pack(side='left', fill='x', expand=True, padx=5, pady=2)
        ttk.Button(frm_dst, text='Parcourir...', command=self.select_dest).pack(side='right', padx=(0, 5))

        # Sélecteur de langue du rapport
        frm_lang = ttk.LabelFrame(self, text='Langue du rapport / Report language')
        frm_lang.pack(fill='x', padx=10, pady=5)
        self.lang_var = tk.StringVar(value='fr')
        ttk.Radiobutton(frm_lang, text='Français', variable=self.lang_var, value='fr').pack(side='left', padx=10)
        ttk.Radiobutton(frm_lang, text='English',  variable=self.lang_var, value='en').pack(side='left', padx=10)

        # Log UART (optionnel) : identité matérielle + RTC
        frm_bl = ttk.LabelFrame(self, text='Log console UART (optionnel) — identité matérielle + horloge')
        frm_bl.pack(fill='x', padx=10, pady=5)
        self.bootlog_path = tk.StringVar()
        ttk.Entry(frm_bl, textvariable=self.bootlog_path).pack(side='left', fill='x', expand=True, padx=5, pady=2)
        ttk.Button(frm_bl, text='Parcourir...', command=self.select_bootlog).pack(side='right', padx=(0, 5))

        # Décalage horloge (optionnel)
        frm_ck = ttk.LabelFrame(self, text="Décalage horloge (optionnel) — corrige date_corrigee")
        frm_ck.pack(fill='x', padx=10, pady=5)
        self.tablet_time = tk.StringVar()
        self.real_time = tk.StringVar(value=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        self.offset_sec = tk.StringVar()
        row1 = ttk.Frame(frm_ck); row1.pack(fill='x', padx=5, pady=2)
        ttk.Label(row1, text='Heure tablette :', width=16).pack(side='left')
        ttk.Entry(row1, textvariable=self.tablet_time, width=22).pack(side='left', padx=4)
        ttk.Label(row1, text='(ou lue dans le log UART si vide)').pack(side='left')
        row2 = ttk.Frame(frm_ck); row2.pack(fill='x', padx=5, pady=2)
        ttk.Label(row2, text='Heure réelle (PC) :', width=16).pack(side='left')
        ttk.Entry(row2, textvariable=self.real_time, width=22).pack(side='left', padx=4)
        ttk.Button(row2, text='↻ heure PC', command=lambda: self.real_time.set(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))).pack(side='left', padx=4)
        ttk.Label(row2, text='(modifiable si PC pas à l\'heure)').pack(side='left')
        row3 = ttk.Frame(frm_ck); row3.pack(fill='x', padx=5, pady=2)
        ttk.Label(row3, text='… ou décalage (s) :', width=16).pack(side='left')
        ttk.Entry(row3, textvariable=self.offset_sec, width=22).pack(side='left', padx=4)
        ttk.Label(row3, text='(tablette − réel, en secondes)').pack(side='left')

        dep_frame = ttk.LabelFrame(self, text="Statut des Dépendances Optionnelles")
        dep_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(dep_frame, textvariable=self.dep_py7zr).pack(anchor='w', padx=5)
        ttk.Separator(dep_frame, orient='horizontal').pack(fill='x', pady=5)
        ttk.Label(dep_frame, textvariable=self.dep_psutil).pack(anchor='w', padx=5)

        self.progress = ttk.Progressbar(self, orient='horizontal', length=640, mode='determinate', variable=self.progress_percentage)
        self.progress.pack(padx=10, pady=(8, 6))
        ttk.Label(self, textvariable=self.progress_message).pack()
        ttk.Label(self, textvariable=self.time_message).pack()
        ttk.Label(self, textvariable=self.res_message).pack()

        btns = ttk.Frame(self)
        btns.pack(pady=10)
        self.btn_start = ttk.Button(btns, text='Analyser', width=18, command=self.start_analysis)
        self.btn_start.pack(side='left', padx=5)
        self.btn_report = ttk.Button(btns, text='📂 Ouvrir le rapport', width=18, command=self.open_report, state='disabled')
        self.btn_report.pack(side='left', padx=5)
        ttk.Button(btns, text='Quitter', width=12, command=self.quit).pack(side='left', padx=5)
        tk.Label(self, text="AFAP v2.3.0 | Créé par Vincent Chapeau", font=("Arial", 9), fg="black").place(relx=1.0, rely=1.0, anchor='se')

    def _check_dependencies(self):
        if PY7ZR_AVAILABLE:
            self.dep_py7zr.set("✅ py7zr : Installé (support des archives .7z)")
        else:
            self.dep_py7zr.set("⚠️ py7zr : Manquant (le support .7z est désactivé). Commande : pip install py7zr")
        self.dep_psutil.set("✅ psutil (monitoring) : Installée" if PSUTIL_AVAILABLE else "⚠️ psutil (monitoring) : Manquant")

    def select_source(self):
        is_file = messagebox.askyesno("Sélection de la source", "La source est-elle un fichier archive (Oui) ou un dossier (Non) ?")
        
        supported_patterns = ["*.zip"]
        if PY7ZR_AVAILABLE:
            supported_patterns.append("*.7z")
        all_patterns_str = " ".join(supported_patterns)
        
        filetypes_list = [
            ("Archives supportées", all_patterns_str),
            ("Tous les fichiers", "*.*")
        ]
        
        if is_file:
            path = filedialog.askopenfilename(title="Sélectionner une archive", filetypes=filetypes_list)
        else:
            path = filedialog.askdirectory(title="Sélectionner un dossier")
            
        if path: self.source_path.set(path)

    def select_dest(self):
        path = filedialog.askdirectory()
        if path: self.dest_path.set(path)

    def select_bootlog(self):
        path = filedialog.askopenfilename(title="Log console UART (.txt/.log)",
                                          filetypes=[("Logs", "*.txt *.log"), ("Tous", "*.*")])
        if path: self.bootlog_path.set(path)

    def _update_ui_loop(self, step=0):
        if self.analysis_is_running:
            elapsed = datetime.datetime.now() - self.start_time
            elapsed_str = str(elapsed).split('.')[0]
            start_str = self.start_time.strftime('%H:%M:%S')
            spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[step]
            self.time_message.set(f"Lancé à {start_str} | Durée: {elapsed_str} | {spinner}")
            if PSUTIL_AVAILABLE:
                cpu, vm = psutil.cpu_percent(interval=None), psutil.virtual_memory()
                self.res_message.set(f"CPU: {cpu:.0f}% | RAM: {human_bytes(vm.used)} / {human_bytes(vm.total)} ({vm.percent:.0f}%)")
            self.after(100, self._update_ui_loop, (step + 1) % 10)
        else:
            if self.start_time: self.time_message.set(f"Analyse terminée en {str(datetime.datetime.now() - self.start_time).split('.')[0]}"); self.res_message.set("")

    def _show_final_summary(self, summary):
        self.analysis_is_running = False
        self._update_ui_loop()
        messagebox.showinfo("Résumé de l\'Analyse", summary)
        self.btn_start.config(text='Analyser', state='normal')
        if self.last_export_dir: self.btn_report.config(state='normal')

    def open_report(self):
        if not self.last_export_dir or not os.path.isdir(self.last_export_dir):
            messagebox.showerror("Erreur", "Le chemin du rapport est introuvable."); return
        # On privilégie le rapport markdown consolidé ; fallback sur la timeline HTML
        candidates = [os.path.join('01_SYNTHESE_ENQUETEUR', 'rapport_forensique.md'),
                      os.path.join('01_SYNTHESE_ENQUETEUR', 'Timeline_interactive.html'),
                      'rapport_forensique.md', 'Timeline_Chronologique.html']
        for candidate in candidates:
            report_path = os.path.join(self.last_export_dir, candidate)
            if os.path.exists(report_path):
                try:
                    webbrowser.open(f"file://{os.path.realpath(report_path)}")
                    return
                except Exception as e:
                    messagebox.showerror("Erreur", f"Impossible d'ouvrir le rapport : {e}")
                    return
        messagebox.showerror("Erreur", "Aucun fichier rapport n'a été trouvé dans le dossier d'export.")

    def start_analysis(self):
        src = self.source_path.get()
        if not src or not self.dest_path.get(): messagebox.showerror("Erreur", "Veuillez sélectionner une source et un dossier d\'export."); return
        if not os.path.exists(src): messagebox.showerror("Erreur", "Le chemin source n\'existe pas."); return
        
        self.btn_start.config(text='Analyse en cours...', state='disabled'); self.btn_report.config(state='disabled')
        self.last_export_dir = None; self.start_time = datetime.datetime.now(); self.analysis_is_running = True
        self._update_ui_loop(); threading.Thread(target=self.run_analysis, daemon=True).start()

    def run_analysis(self):
        source_path, dst_path = self.source_path.get(), self.dest_path.get()
        # --- LA LOGIQUE DE DÉCOMPRESSION EST SUPPRIMÉE ---
        # La source est passée directement aux modules
        source_to_scan = source_path
        try:
            import py7zr
            print(f"DEBUG: py7zr version: {py7zr.__version__}")
            self.progress_message.set("Initialisation..."); self.progress_percentage.set(0)
            
            # Note: get_tablet_info utilisera la nouvelle API VFS de core_scanner
            tablet_info = get_tablet_info(source_to_scan)
            serial = tablet_info.get('serial', 'inconnu')
            export_dir = os.path.join(dst_path, f"Analyse_{serial}_{self.start_time.strftime('%Y%m%d_%H%M%S')}")
            os.makedirs(export_dir, exist_ok=True)
            setup_logging(export_dir)
            export_tablet_info_csv(export_dir, tablet_info)
            self.last_export_dir = export_dir

            script_dir = os.path.dirname(os.path.abspath(__file__))
            skiplist_file = os.path.join(script_dir, 'hash_skiplist.txt')
            skip_md5 = {line.strip().lower() for line in open(skiplist_file, 'r', encoding='utf-8') if line.strip()} if os.path.isfile(skiplist_file) else set()
            
            _set_lang(self.lang_var.get())  # bascule i18n FR/EN pour le rapport

            # --- Décalage horloge : heure tablette (champ, sinon RTC du log UART) ---
            bootlog = self.bootlog_path.get().strip() or None
            tt = self.tablet_time.get().strip()
            if not tt and bootlog:
                tt = detect_tablet_time(bootlog)
            rt = self.real_time.get().strip() or None
            osec = None
            if self.offset_sec.get().strip():
                try: osec = int(self.offset_sec.get().strip())
                except ValueError: osec = None
            clock = ClockOffset.from_args(tablet_time=(tt or None), real_time=rt, offset_seconds=osec)
            clock.to_json(export_dir)
            scelle = os.path.basename(os.path.abspath(source_to_scan).rstrip('/\\'))

            modules_to_run = [
                # --- Modules historiques (CSV core) ---
                ("Extraction des VINs",                    extract_all_vins),
                ("Extraction des événements de logs",      extract_all_log_events),
                ("Extraction des adresses MAC",            extract_mac),
                ("Extraction des utilisateurs et URLs",    extract_user_and_endpoints),
                ("Extraction des mots de passe",           extract_passwords),
                ("Extraction des références véhicule",     extract_vehicle_refs),
                ("Copie des médias DCIM",                  extract_dcim_media),
                ("Export des tables SQLite",               export_sqlite_tables),
                # --- Modules ajoutés en v2.0.0 ---
                ("Opérations véhicule (CloudEData)",       extract_cloud_e_data),
                ("Usage par marque (.FREQUENCY)",          extract_module_usage),
                ("Logs VCI (.VciLog)",                     extract_vci_logs),
                ("ES File Explorer (historique + apps)",   extract_es_history),
                ("Stockage externe SD/USB",                extract_external_storage),
                ("Secrets / certificats / clés",           extract_secrets),
                ("EventLog applicatif",                    extract_event_log),
                ("WAL SQLite (indicateurs)",               extract_wal_indicators),
                # --- Modules v2.2/2.3 ---
                ("Identité compte (userId)",               extract_account),
                ("Log UART (identité matérielle)",         parse_uart_bootlog),
                ("WiFi / tethering",                       extract_wifi),
                ("Bluetooth (appareils appairés)",         extract_bluetooth),
                ("QR KYC (photos DCIM)",                   extract_kyc_qr),
                # --- Rapports (lisent les CSV produits — toujours en dernier) ---
                ("Création de la Timeline",                create_timeline_report),
                ("Rapport forensique consolidé",           create_forensic_report),
                ("Table maître (import Mercure)",          create_master_timeline),
                ("Timeline interactive (décalage)",        create_timeline_html),
                ("Rangement de l'export",                  finalize_export),
            ]
            results = {}; total_modules = len(modules_to_run); base_progress = 10.0
            for i, (name, func) in enumerate(modules_to_run, 1):
                module_weight = 90.0 / total_modules
                self.progress_message.set(f"Module ({i}/{total_modules}): {name}...")
                self.progress_percentage.set(base_progress)
                try:
                    args = {"src_dir": source_to_scan, "export_dir": export_dir, "skip_md5": skip_md5,
                            "clock": clock, "serial": serial, "scelle": scelle,
                            "bootlog": bootlog, "real_time": rt}
                    if name == "Export des tables SQLite":
                        args["tables"] = ['tb_history_menu', 'tb_user_info', 'tb_vci_record']
                    result = func(**args)
                    results[name] = len(result) if result is not None else 0
                except Exception:
                    logging.exception(f"ERREUR CRITIQUE dans le module {name}")
                    results[name] = "Erreur"
                base_progress += module_weight

            self.progress_message.set("Génération des rapports…"); self.progress_percentage.set(100)
            unit_labels = {"Extraction des VINs": "VINs", "Copie des médias DCIM": "fichiers", "Export des tables SQLite": "tables"}
            summary = "Analyse terminée avec succès !\n\n"
            for name, count in results.items():
                unit = unit_labels.get(name, "artéfacts")
                if isinstance(count, int):
                    summary += f"- {name}: {count} {unit} trouvés\n"
                else:
                    summary += f"- {name}: {count}\n"
            self.after(0, self._show_final_summary, summary)
        except Exception as e:
            logging.exception("Une erreur fatale est survenue durant l'analyse.")
            self.progress_message.set("Erreur Fatale !")
            messagebox.showerror("Erreur Fatale", f"L'analyse a échoué.\n\nErreur: {e}")
            self.btn_start.config(text='Analyser', state='normal')
        finally:
            self.analysis_is_running = False


if __name__ == '__main__':
    app = AutelApp()
    app.mainloop()
