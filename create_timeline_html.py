# create_timeline_html.py — AFAP
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Génère une application HTML autonome (Timeline_interactive.html) à partir de
# la table maître (Chronologie_MAITRE.csv). Fonctions :
#   - filtres déroulants : catégorie, constructeur, période (mois), plage de
#     dates, recherche libre ;
#   - colonne MAC dédiée ;
#   - **saisie du décalage horloge constaté à l'extraction** (heure tablette /
#     heure réelle, OU secondes) : la colonne « heure corrigée » est recalculée
#     EN DIRECT dans le navigateur ;
#   - export CSV du sous-ensemble filtré.
#
# N'enlève ni ne remplace create_timeline_report (HTML historique) : module
# complémentaire.

import os
import csv
import json
import logging
from core_scanner import open_csv  # noqa: F401  (cohérence d'import projet)


def _load_master(export_dir):
    p = os.path.join(export_dir, 'Chronologie_MAITRE.csv')
    if not os.path.isfile(p):
        return []
    with open(p, encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def create_timeline_html(src_dir, export_dir, skip_md5=None, clock=None, **kwargs):
    rows = _load_master(export_dir)
    if not rows:
        logging.warning("create_timeline_html : Chronologie_MAITRE.csv absent (lancer 'master' avant).")
        return []
    preset = 0
    try:
        preset = int(getattr(clock, 'offset_seconds', 0) or 0)
    except Exception:
        preset = 0
    data = json.dumps(rows, ensure_ascii=False)
    html = _TEMPLATE.replace("__DATA__", data).replace("__PRESET__", str(preset))
    out = os.path.join(export_dir, 'Timeline_interactive.html')
    with open(out, 'w', encoding='utf-8') as f:
        f.write(html)
    logging.info(f"create_timeline_html : {len(rows)} événements -> {out}")
    return rows


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Chronologie AFAP</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--acc:#38bdf8;--txt:#e2e8f0;--mut:#94a3b8;--op:#f59e0b;--ee:#ef4444;--se:#3b82f6;--ac:#22c55e;--ap:#a855f7;--rz:#14b8a6;--bt:#eab308;--dv:#64748b}
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--txt);font-size:14px}
header{padding:16px 22px;background:linear-gradient(90deg,#0b1220,#1e293b);border-bottom:2px solid var(--acc)}
header h1{margin:0;font-size:18px}header p{margin:4px 0 0;color:var(--mut);font-size:12px}
.wrap{padding:14px 22px;max-width:1320px;margin:0 auto}
.panel{background:var(--card);padding:12px 14px;border-radius:10px;margin-bottom:12px}
.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end}
.f{display:flex;flex-direction:column;gap:4px}.f label{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
select,input{background:#0f172a;color:var(--txt);border:1px solid #334155;border-radius:6px;padding:7px 9px;font-size:13px;min-width:140px}
button{background:var(--acc);color:#0b1220;border:0;border-radius:6px;padding:8px 13px;font-weight:600;cursor:pointer}
button.sec{background:#334155;color:var(--txt)}
.clock{border:1px solid #334155;border-left:3px solid var(--acc)}
.clock .row{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end}
.clock .note{color:var(--mut);font-size:12px;margin-top:6px}
.kpis{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.kpi{background:var(--card);border-radius:10px;padding:10px 14px;flex:1;min-width:110px;border-left:3px solid var(--acc)}
.kpi b{font-size:20px;display:block}.kpi span{color:var(--mut);font-size:11px}
table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #334155;font-size:13px;vertical-align:top}
th{background:#0b1220;color:var(--acc);cursor:pointer;position:sticky;top:0;white-space:nowrap}
tr:hover td{background:#243449}
.tag{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;color:#0b1220;white-space:nowrap}
.corr{color:var(--ac);font-weight:600}.src{color:var(--mut);font-size:11px;word-break:break-all}
.mac{font-family:monospace;font-size:12px;color:#cbd5e1}
.foot{margin-top:14px;color:var(--mut);font-size:11px;line-height:1.6}
</style></head><body>
<header><h1>Chronologie interactive — AFAP</h1>
<p>Table maître consolidée. Heures = horloge RTC de la tablette. Renseignez le décalage constaté à l'extraction pour obtenir l'heure corrigée.</p></header>
<div class="wrap">

<div class="panel clock">
 <div class="row">
  <div class="f"><label>Heure affichée sur la tablette</label><input type="datetime-local" id="ctab" step="1"></div>
  <div class="f"><label>Heure réelle (PC — modifiable)</label><input type="datetime-local" id="creal" step="1"></div>
  <div class="f"><label>… ou décalage direct (secondes)</label><input type="number" id="coff" placeholder="ex: 180"></div>
  <button onclick="applyClock()">Appliquer</button>
  <button class="sec" onclick="clearClock()">Aucun décalage</button>
 </div>
 <div class="note" id="cnote">« Heure réelle » est pré-remplie avec l'horloge du PC (corrigez-la si le PC n'est pas à l'heure). Décalage = heure tablette − heure réelle ; heure corrigée = heure enregistrée − décalage.</div>
</div>

<div class="panel filters">
 <div class="f"><label>Catégorie</label><select id="fcat"></select></div>
 <div class="f"><label>Constructeur</label><select id="fconstr"></select></div>
 <div class="f"><label>Période (mois)</label><select id="fmonth"></select></div>
 <div class="f"><label>Du</label><input type="date" id="ffrom"></div>
 <div class="f"><label>Au</label><input type="date" id="fto"></div>
 <div class="f"><label>Recherche</label><input type="text" id="fq" placeholder="modèle, fonction, MAC, fichier…"></div>
 <button class="sec" onclick="resetF()">Réinitialiser</button>
 <button onclick="expo()">Exporter CSV filtré</button>
</div>

<div class="kpis" id="kpis"></div>
<table id="tbl"><thead><tr>
 <th data-k="horodatage">Heure tablette ▲</th><th data-k="__corr">Heure corrigée</th>
 <th data-k="categorie">Catégorie</th><th data-k="constructeur">Constr.</th>
 <th data-k="modele">Modèle</th><th data-k="operation">Opération</th>
 <th data-k="detail">Détail</th><th data-k="mac_address">MAC</th><th data-k="source_fichier">Source</th>
</tr></thead><tbody id="tb"></tbody></table>
<div class="foot" id="foot"></div>
</div>
<script>
const DATA=__DATA__;
let OFFSET=parseInt("__PRESET__")||0;
const COL={'Opération clé':'--op','Lecture EEPROM immobiliseur':'--ee','Session diagnostic':'--se','Compte Autel':'--ac','Connexion compte':'--ac','Média (photo)':'--ap','Réseau':'--rz','Bluetooth':'--bt','Appareil':'--dv','Session applicative':'--ap'};
const cv=v=>getComputedStyle(document.documentElement).getPropertyValue(v)||'#38bdf8';
let sortK='horodatage',sortAsc=true;
function pad(n){return String(n).padStart(2,'0')}
function corr(hor){ if(!OFFSET||!hor||hor.length<19)return ''; let d=new Date(hor.replace(' ','T')); if(isNaN(d))return ''; d=new Date(d.getTime()-OFFSET*1000);
 return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+' '+pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds()); }
function uniq(k){return [...new Set(DATA.map(r=>r[k]).filter(Boolean))].sort()}
function fill(id,vals,lab){document.getElementById(id).innerHTML='<option value="">'+lab+'</option>'+vals.map(v=>`<option>${v}</option>`).join('')}
fill('fcat',uniq('categorie'),'Toutes');fill('fconstr',uniq('constructeur'),'Tous');
fill('fmonth',[...new Set(DATA.map(r=>(r.date_tablette||'').slice(0,7)).filter(Boolean))].sort(),'Toutes');
function applyClock(){ let off=document.getElementById('coff').value, t=document.getElementById('ctab').value, r=document.getElementById('creal').value;
 if(off!==''){OFFSET=parseInt(off)||0;} else if(t&&r){OFFSET=Math.round((new Date(t)-new Date(r))/1000);} else {OFFSET=0;}
 document.getElementById('cnote').textContent = OFFSET? ('Décalage appliqué : '+(OFFSET>0?'+':'')+OFFSET+' s (tablette '+(OFFSET>0?'en avance':'en retard')+'). Heure corrigée = heure tablette − ('+(OFFSET>0?'+':'')+OFFSET+' s).') : 'Aucun décalage appliqué.'; render(); }
function clearClock(){OFFSET=0;document.getElementById('coff').value='';document.getElementById('ctab').value='';document.getElementById('creal').value='';document.getElementById('cnote').textContent='Aucun décalage appliqué.';render();}
function flt(){let c=fcat.value,co=fconstr.value,m=fmonth.value,fr=ffrom.value,to=fto.value,q=fq.value.toLowerCase();
 return DATA.filter(r=>{if(c&&r.categorie!==c)return false;if(co&&r.constructeur!==co)return false;
  if(m&&(r.date_tablette||'').slice(0,7)!==m)return false;if(fr&&(r.date_tablette||'')<fr)return false;if(to&&(r.date_tablette||'')>to)return false;
  if(q&&!((r.modele||'')+' '+(r.operation||'')+' '+(r.detail||'')+' '+(r.mac_address||'')+' '+(r.source_fichier||'')+' '+(r.categorie||'')).toLowerCase().includes(q))return false;return true;});}
function render(){let rows=flt().slice().sort((a,b)=>{let x=(sortK=='__corr'?corr(a.horodatage):a[sortK])||'',y=(sortK=='__corr'?corr(b.horodatage):b[sortK])||'';return (x>y?1:x<y?-1:0)*(sortAsc?1:-1)});
 let cats={};rows.forEach(r=>cats[r.categorie]=(cats[r.categorie]||0)+1);
 let k=`<div class="kpi"><b>${rows.length}</b><span>événements</span></div>`;
 k+=`<div class="kpi" style="border-color:${cv('--op')}"><b>${cats['Opération clé']||0}</b><span>opérations clé</span></div>`;
 k+=`<div class="kpi" style="border-color:${cv('--ee')}"><b>${cats['Lecture EEPROM immobiliseur']||0}</b><span>EEPROM</span></div>`;
 k+=`<div class="kpi" style="border-color:${cv('--rz')}"><b>${cats['Réseau']||0}</b><span>réseau</span></div>`;
 k+=`<div class="kpi" style="border-color:${cv('--bt')}"><b>${cats['Bluetooth']||0}</b><span>bluetooth</span></div>`;
 kpis.innerHTML=k;
 tb.innerHTML=rows.map(r=>{let c=cv(COL[r.categorie]||'--dv');let cc=corr(r.horodatage);
  return `<tr><td>${r.horodatage||r.date_tablette||''}</td><td class="corr">${cc||'—'}</td>
   <td><span class="tag" style="background:${c}">${r.categorie||''}</span></td>
   <td>${r.constructeur||''}</td><td>${r.modele||''}</td><td>${r.operation||''}</td>
   <td>${r.detail||''}</td><td class="mac">${r.mac_address||''}</td><td class="src">${r.source_fichier||''}</td></tr>`}).join('');
 foot.textContent=`${rows.length} / ${DATA.length} événements. `+(OFFSET?('Décalage horloge : '+(OFFSET>0?'+':'')+OFFSET+' s.'):'Décalage non renseigné : la colonne « heure corrigée » reste vide.');}
document.querySelectorAll('th').forEach(th=>th.onclick=()=>{let k=th.dataset.k;if(sortK===k)sortAsc=!sortAsc;else{sortK=k;sortAsc=true}
 document.querySelectorAll('th').forEach(t=>t.textContent=t.textContent.replace(/[▲▼]/g,'').trim());th.textContent=th.textContent+' '+(sortAsc?'▲':'▼');render()});
['fcat','fconstr','fmonth','ffrom','fto','fq'].forEach(id=>document.getElementById(id).addEventListener('input',render));
function resetF(){['fcat','fconstr','fmonth','ffrom','fto','fq'].forEach(id=>document.getElementById(id).value='');render()}
function expo(){let rows=flt();let cols=['no','date_tablette','heure_tablette','heure_corrigee','categorie','constructeur','modele','operation','detail','mac_address','fiabilite','scelle','sn_tablette','compte_autel','source_fichier'];
 let out=cols.join(',')+'\n'+rows.map(r=>{let o={...r,heure_corrigee:corr(r.horodatage)};return cols.map(c=>'"'+String(o[c]||'').replace(/"/g,'""')+'"').join(',')}).join('\n');
 let b=new Blob(['﻿'+out],{type:'text/csv'});let a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='chronologie_filtree.csv';a.click();}
function prefillRealTime(){var d=new Date();var q=function(n){return String(n).padStart(2,'0')};
 document.getElementById('creal').value=d.getFullYear()+'-'+q(d.getMonth()+1)+'-'+q(d.getDate())+'T'+q(d.getHours())+':'+q(d.getMinutes())+':'+q(d.getSeconds());}
prefillRealTime();
render();
</script></body></html>"""
