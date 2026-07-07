"""Self-contained HTML "radar" dashboard exporter.

Emits a single standalone HTML file — no external scripts, styles, or fonts — so
it renders offline / air-gapped (a hard requirement for a security tool). The
report is embedded as a JSON blob and rendered entirely client-side with vanilla
JS that writes values via ``textContent`` only. Certificate subjects, SANs and
issuer names are attacker-controlled, so nothing untrusted is ever interpolated
into markup: there is no ``innerHTML`` of report data, and every markup-
significant character in the embedded JSON (``<`` ``>`` ``&`` plus the U+2028 /
U+2029 line separators) is escaped to a ``\\uXXXX`` form. That neutralises not
just ``</script`` but also ``<!--`` and ``<script`` — the gadgets that would
otherwise push the HTML tokenizer into script-data-(double-)escaped state and
swallow the renderer — so attacker-controlled values cannot terminate, corrupt,
or blank the document. The escapes round-trip losslessly through ``JSON.parse``.
"""

from __future__ import annotations

import json
from typing import Optional

from .. import __version__
from ..models import EndpointReport, to_serializable
from ..report import migration_map


def to_html(reports: list[EndpointReport], meta: Optional[dict] = None) -> str:
    meta = meta or {}
    data = {
        "meta": {
            "tool_version": meta.get("tool_version", __version__),
            "generated_at": meta.get("generated_at"),
            "openssl": meta.get("openssl"),
            "endpoints": len(reports),
            "reachable": sum(1 for r in reports if r.scan.reachable),
        },
        "migration": migration_map(reports),
        "endpoints": [to_serializable(r) for r in reports],
    }
    # Safe embedding in a <script> element: escape every markup-significant
    # character so no attacker-controlled value can terminate the element or
    # drive the tokenizer into script-data-escaped state (</script, <!--, <script).
    payload = (json.dumps(data)
               .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
               .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
    return _TEMPLATE.replace("/*__QER_DATA__*/", payload)


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GreyNOC Quantum Exposure Radar</title>
<style>
  :root{
    --bg:#0a0e14; --panel:#11161f; --panel2:#0d1219; --line:#1f2733;
    --text:#c9d1d9; --dim:#7d8794; --bold:#e6edf3;
    --crit:#ff4d4f; --high:#ff7a45; --med:#ffc53d; --low:#36cfc9; --info:#6b7681;
    --ok:#3fb950; --accent:#58a6ff; --pq:#3fb950;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  a{color:var(--accent)}
  .wrap{max-width:1100px;margin:0 auto;padding:28px 20px 64px}
  header h1{margin:0;font-size:20px;color:var(--bold);letter-spacing:.3px}
  header h1 .q{color:var(--pq)}
  .sub{color:var(--dim);margin:4px 0 18px}
  .chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 24px}
  .chip{border:1px solid var(--line);border-radius:6px;padding:5px 10px;background:var(--panel)}
  .chip b{color:var(--bold)}
  .sev-crit{color:var(--crit)} .sev-high{color:var(--high)} .sev-med{color:var(--med)}
  .sev-low{color:var(--low)} .sev-info{color:var(--info)}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);
    border-bottom:1px solid var(--line);padding-bottom:6px;margin:30px 0 14px}
  .wave{margin:0 0 16px}
  .wave-title{font-weight:bold;margin:0 0 6px}
  .row{display:grid;grid-template-columns:1fr 220px;gap:12px;align-items:center;
    padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel);margin:6px 0}
  .row .name{color:var(--bold)} .row .label{color:var(--dim)}
  .bar{height:8px;border-radius:4px;background:var(--panel2);overflow:hidden;border:1px solid var(--line)}
  .bar > i{display:block;height:100%}
  .metrics{color:var(--dim);font-size:12px;margin-top:4px}
  .qw{color:var(--ok);font-size:11px;border:1px solid var(--ok);border-radius:4px;padding:1px 5px;margin-left:6px}
  .cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px}
  .card{border:1px solid var(--line);border-radius:8px;background:var(--panel);padding:14px 16px}
  .card .top{display:flex;justify-content:space-between;align-items:baseline;gap:8px}
  .card .ep{color:var(--bold);font-weight:bold;word-break:break-all}
  .pri{font-size:11px;border-radius:4px;padding:2px 7px;border:1px solid currentColor}
  .pri-NOW{color:var(--crit)} .pri-SOON{color:var(--med)} .pri-LATER{color:var(--low)}
  .pri-OK{color:var(--ok)} .pri-UNREACHABLE{color:var(--info)}
  .kv{color:var(--dim);font-size:12px;margin:8px 0 0;white-space:pre-wrap;word-break:break-word}
  .kv b{color:var(--text);font-weight:normal}
  .pq{margin-top:6px;font-size:12px}
  .pq.green{color:var(--pq)} .pq.amber{color:var(--med)} .pq.red{color:var(--high)}
  .chain{margin:8px 0 0;font-size:12px;color:var(--dim)}
  .chain div{padding:1px 0}
  .pos{display:inline-block;min-width:84px;color:var(--accent)}
  .findings{margin:10px 0 0;list-style:none;padding:0}
  .findings li{padding:3px 0;font-size:12px;border-top:1px dashed var(--line)}
  .tag{display:inline-block;min-width:42px;font-weight:bold}
  .id{color:var(--dim)}
  footer{color:var(--dim);margin-top:36px;font-size:12px}
  .warn{color:var(--crit)}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>GreyNOC <span class="q">Quantum Exposure</span> Radar</h1>
    <div class="sub" id="sub"></div>
    <div class="chips" id="chips"></div>
  </header>
  <h2>Executive migration map</h2>
  <div id="map"></div>
  <h2>Cryptographic bill of materials</h2>
  <div class="cards" id="cards"></div>
  <footer id="foot"></footer>
</div>
<script id="qer-data" type="application/json">/*__QER_DATA__*/</script>
<script>
"use strict";
var QER = JSON.parse(document.getElementById("qer-data").textContent);
var SEV = ["info","low","medium","high","critical"];
var SEVCLASS = {critical:"sev-crit",high:"sev-high",medium:"sev-med",low:"sev-low",info:"sev-info"};
var SEVTAG = {critical:"CRIT",high:"HIGH",medium:"MED",low:"LOW",info:"INFO"};

function el(tag, cls, text){
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = String(text);   // textContent: never interprets markup
  return e;
}
function barColor(v){ return v>=70?"var(--crit)":v>=45?"var(--med)":v>=20?"var(--low)":"var(--ok)"; }

(function summary(){
  var m = QER.meta || {};
  document.getElementById("sub").textContent =
    "v" + (m.tool_version||"") + "  ·  " + (m.generated_at||"") +
    (m.openssl ? "  ·  " + m.openssl : "");
  var counts = {critical:0,high:0,medium:0,low:0,info:0};
  (QER.endpoints||[]).forEach(function(r){
    (r.findings||[]).forEach(function(f){ if(counts[f.severity]!=null) counts[f.severity]++; });
  });
  var chips = document.getElementById("chips");
  var c1 = el("span","chip"); c1.append(document.createTextNode("endpoints "));
  c1.append(el("b",null,(m.endpoints||0)+" ("+(m.reachable||0)+" reachable)")); chips.append(c1);
  SEV.slice().reverse().forEach(function(s){
    var ch = el("span","chip "+SEVCLASS[s]);
    ch.append(document.createTextNode(SEVTAG[s]+" "));
    ch.append(el("b",null,counts[s])); chips.append(ch);
  });
})();

(function map(){
  var waves = [["NOW","Wave 1 — migrate now"],["SOON","Wave 2 — soon"],
    ["LATER","Wave 3 — later"],["OK","Defer — acceptable for now"],
    ["UNREACHABLE","Unreachable"]];
  var host = document.getElementById("map");
  (waves).forEach(function(w){
    var group = (QER.migration||[]).filter(function(x){return x.priority===w[0];});
    if(!group.length) return;
    var box = el("div","wave");
    box.append(el("div","wave-title pri-"+w[0], w[1]+" ("+group.length+")"));
    group.forEach(function(x){
      var row = el("div","row");
      var left = el("div");
      var nm = el("span","name", x.endpoint);
      left.append(nm);
      if(x.label){ left.append(document.createTextNode("  ")); left.append(el("span","label",x.label)); }
      if(x.quick_win){ left.append(el("span","qw","★ quick win")); }
      if(w[0] !== "UNREACHABLE"){
        var met = el("div","metrics","risk "+x.risk_score+"   hndl "+x.hndl_risk+"   diff "+x.migration_difficulty+"   ready "+x.readiness);
        left.append(met);
      }
      row.append(left);
      var bar = el("div","bar");
      var fill = el("i"); fill.style.width = Math.max(2,x.risk_score)+"%"; fill.style.background = barColor(x.risk_score);
      bar.append(fill); row.append(bar);
      box.append(row);
    });
    host.append(box);
  });
})();

(function cards(){
  var host = document.getElementById("cards");
  (QER.endpoints||[]).forEach(function(r){
    var scan = r.scan||{}, sc = r.scores||{}, prof = r.profile||{};
    var card = el("div","card");
    var top = el("div","top");
    top.append(el("span","ep", scan.host+":"+scan.port));
    var pri = sc.priority||"?";
    top.append(el("span","pri pri-"+pri, pri));
    card.append(top);

    if(!scan.reachable){
      card.append(el("div","kv warn", "unreachable — " + (scan.error||"no TLS handshake")));
      host.append(card); return;
    }

    var kv = el("div","kv");
    kv.append(document.createTextNode(
      (scan.negotiated_version||"?")+"  "+(scan.negotiated_cipher||"")+"\n"+
      "kex "+(scan.key_exchange||"?")+"   fs "+(scan.forward_secret?"yes":(scan.forward_secret===false?"NO":"?"))+
      "   risk "+(sc.risk_score!=null?sc.risk_score:"?")+"   hndl "+(sc.hndl_risk!=null?sc.hndl_risk:"?")));
    card.append(kv);
    if((scan.weak_versions||[]).length){
      card.append(el("div","kv warn","legacy accepted: "+scan.weak_versions.join(", ")));
    }
    if(scan.legacy_only){
      card.append(el("div","kv warn","legacy-only (handshake required SECLEVEL=0)"));
    }

    if(scan.pq_testable){
      var sup = scan.pq_groups_supported||[];
      var pq;
      if(sup.length){
        pq = el("div","pq "+(scan.pq_preferred?"green":"amber"),
          "PQ kex: "+sup.join(", ")+(scan.pq_preferred?" (enforced)":" (classical accepted)"));
      } else { pq = el("div","pq red","PQ kex: none (classical only)"); }
      card.append(pq);
    }

    if((scan.certificates||[]).length){
      var chain = el("div","chain");
      scan.certificates.forEach(function(c){
        var line = el("div");
        line.append(el("span","pos","["+(c.position||"leaf")+"]"));
        var keyd = c.public_key_algorithm + (c.public_key_bits?("-"+c.public_key_bits):"");
        var txt = keyd + (c.public_key_curve?(" "+c.public_key_curve):"") + "  sig "+c.signature_algorithm;
        if(c.position==="leaf" && c.days_to_expiry!=null) txt += "  exp "+c.days_to_expiry+"d";
        line.append(document.createTextNode("  "+txt));
        chain.append(line);
      });
      card.append(chain);
    }

    var fl = (r.findings||[]).slice().sort(function(a,b){return SEV.indexOf(b.severity)-SEV.indexOf(a.severity);});
    if(fl.length){
      var ul = el("ul","findings");
      fl.forEach(function(f){
        var li = el("li");
        li.append(el("span","tag "+SEVCLASS[f.severity], SEVTAG[f.severity]||"INFO"));
        li.append(document.createTextNode(" "));
        li.append(el("span","id", f.id));
        li.append(document.createTextNode("  "+f.title));
        ul.append(li);
      });
      card.append(ul);
    }
    host.append(card);
  });
})();

document.getElementById("foot").textContent =
  "Generated by GreyNOC Quantum Exposure Radar · self-contained, offline · github.com/GreyNOC/QER";
</script>
</body>
</html>
"""
