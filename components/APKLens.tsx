"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, AlertCircle, Archive, Box, CheckCircle2, ChevronDown, ChevronRight,
  Code2, FileCode2, FileText, Folder, Globe, KeyRound, LayoutDashboard,
  Lock, Package, Search, Server, ShieldCheck, Smartphone, Trash2, Upload,
  XCircle, Zap
} from "lucide-react";
import { analyzeAPK } from "@/lib/apk-analyzer";
import { clearAnalyses, deleteAnalysis, listAnalyses, saveAnalysis } from "@/lib/local-db";
import type { APKAnalysis } from "@/types/apk";

type Tab = "Overview"|"Files"|"Manifest"|"Permissions"|"Components"|"Code"|"Resources"|"Network"|"Security"|"Signing"|"Technology"|"Reports";

const tabs: {id: Tab; label: string; icon: React.ReactNode}[] = [
  {id:"Overview",label:"Overview",icon:<LayoutDashboard size={16}/>},
  {id:"Files",label:"File Explorer",icon:<Folder size={16}/>},
  {id:"Manifest",label:"AndroidManifest",icon:<FileCode2 size={16}/>},
  {id:"Permissions",label:"Permissions",icon:<Lock size={16}/>},
  {id:"Components",label:"Components",icon:<Activity size={16}/>},
  {id:"Code",label:"DEX / Code",icon:<Code2 size={16}/>},
  {id:"Resources",label:"Resources",icon:<Archive size={16}/>},
  {id:"Network",label:"Network & URLs",icon:<Globe size={16}/>},
  {id:"Security",label:"Security Analysis",icon:<ShieldCheck size={16}/>},
  {id:"Signing",label:"Certificate & Signing",icon:<KeyRound size={16}/>},
  {id:"Technology",label:"Technology Detection",icon:<Zap size={16}/>},
  {id:"Reports",label:"Reports",icon:<FileText size={16}/>}
];

export default function APKLens() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [analysis, setAnalysis] = useState<APKAnalysis | null>(null);
  const [history, setHistory] = useState<APKAnalysis[]>([]);
  const [tab, setTab] = useState<Tab>("Overview");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [drag, setDrag] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => { listAnalyses().then(setHistory).catch(() => {}); }, []);

  async function run(file?: File) {
    setError("");
    const f = file ?? inputRef.current?.files?.[0];
    if (!f) return;
    if (!f.name.toLowerCase().endsWith(".apk")) { setError("Please select an .apk file."); return; }
    setBusy(true);
    try {
      const result = await analyzeAPK(f);
      await saveAnalysis(result);
      setAnalysis(result);
      setHistory(await listAnalyses());
      setTab("Overview");
    } catch (e) {
      setError(e instanceof Error ? e.message : "The APK could not be analyzed.");
    } finally { setBusy(false); }
  }

  async function remove(id: string) {
    await deleteAnalysis(id);
    const h = await listAnalyses();
    setHistory(h);
    if (analysis?.id === id) setAnalysis(h[0] ?? null);
  }

  async function clearAll() {
    await clearAnalyses();
    setHistory([]);
    setAnalysis(null);
  }

  function downloadJSON() {
    if (!analysis) return;
    const blob = new Blob([JSON.stringify(analysis, null, 2)], {type:"application/json"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href=url; a.download=`${analysis.fileName.replace(/\.apk$/i,"")}-analysis.json`; a.click();
    URL.revokeObjectURL(url);
  }

  const filteredFiles = useMemo(() =>
    (analysis?.files ?? []).filter(f => f.path.toLowerCase().includes(query.toLowerCase())), [analysis, query]);

  type StatItem = { label: string; value: number; icon: React.ComponentType<{ size?: number }> };
  const stats: StatItem[] = analysis ? [
    { label: "Permissions", value: analysis.permissions.length, icon: Lock },
    { label: "Activities", value: analysis.activities.length, icon: Smartphone },
    { label: "Services", value: analysis.services.length, icon: Server },
    { label: "Receivers", value: analysis.receivers.length, icon: Activity },
    { label: "Providers", value: analysis.providers.length, icon: Box },
    { label: "DEX Files", value: analysis.dexFiles.length, icon: Code2 }
  ] : [];

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand"><div className="brandmark"><Box size={23}/></div><div><b>APKLens</b><span>Analyze. Explore. Understand.</span></div></div>
        <nav><a>Home</a><a>Features</a><a>Privacy</a><a>About</a></nav>
        <div className="top-actions"><div className="privacy"><CheckCircle2 size={14}/> No login · No permanent storage</div><button className="primary" onClick={()=>inputRef.current?.click()}><Upload size={15}/> Analyze New APK</button></div>
      </header>

      <input ref={inputRef} type="file" accept=".apk,application/vnd.android.package-archive" hidden onChange={e=>run(e.target.files?.[0])}/>

      <div className="body">
        <aside className="sidebar">
          <div className="side-label">ANALYSIS</div>
          {tabs.map(t=><button key={t.id} className={tab===t.id?"side-item active":"side-item"} onClick={()=>setTab(t.id)}>{t.icon}<span>{t.label}</span></button>)}
          <div className="side-divider"/>
          <div className="side-label recent-label">RECENT ANALYSES <button onClick={clearAll}>Clear All</button></div>
          {history.slice(0,5).map(h=><button key={h.id} className="history" onClick={()=>{setAnalysis(h);setTab("Overview")}}><Globe size={14}/><span><b>{h.fileName}</b><small>{new Date(h.analyzedAt).toLocaleString()}</small></span></button>)}
          <div className="privacy-card"><ShieldCheck size={18}/><b>Your Privacy Matters</b><span>Browser analysis stays on this device. Full server analysis is not included in this build.</span></div>
        </aside>

        <section className="content">
          {!analysis ? (
            <div className="upload-screen" onDragOver={e=>{e.preventDefault();setDrag(true)}} onDragLeave={()=>setDrag(false)} onDrop={e=>{e.preventDefault();setDrag(false);run(e.dataTransfer.files[0])}}>
              <div className={drag?"dropzone drag":"dropzone"}><div className="upload-icon"><Upload size={30}/></div><h1>Analyze an Android APK</h1><p>Inspect the APK structure, manifest, DEX files, resources, URLs and security indicators directly in your browser.</p><button className="primary big" onClick={()=>inputRef.current?.click()}><Upload size={17}/> Choose APK</button><span className="drop-hint">or drag and drop an .apk file here</span><div className="privacy-line"><Lock size={14}/> Local-first · No login · No permanent server storage</div></div>
              <div className="feature-grid"><Feature icon={<ShieldCheck/>} title="Privacy-first" text="The browser analyzer keeps results in IndexedDB on your device."/><Feature icon={<Search/>} title="Evidence-based" text="Findings are generated from artifacts actually present in the APK."/><Feature icon={<Code2/>} title="Deep inspection" text="Explore DEX, resources, native libraries, URLs and manifest data."/><Feature icon={<Zap/>} title="Fast" text="No upload is required for the included browser-based analyzer." /></div>
              {error && <div className="error"><AlertCircle size={16}/>{error}</div>}
            </div>
          ) : (
            <>
              <div className="analysis-head">
                <div className="app-title"><div className="android-icon"><Smartphone size={30}/></div><div><h1>{analysis.fileName}</h1><div className="badges"><span className="success"><CheckCircle2 size={13}/> Analyzed successfully</span><span className="blue">Local Analysis</span><span className="muted">{new Date(analysis.analyzedAt).toLocaleString()}</span></div><p>{analysis.packageName ?? "Package could not be decoded in browser-only mode."}</p></div></div>
                <div className="head-actions"><button className="secondary" onClick={downloadJSON}><FileText size={15}/> Download JSON</button><button className="danger" onClick={()=>remove(analysis.id)}><Trash2 size={15}/> Clear Analysis</button></div>
              </div>

              <div className="meta-grid">
                <Meta label="App Name" value={analysis.fileName.replace(/\.apk$/i,"")}/>
                <Meta label="Package" value={analysis.packageName ?? "Not decoded"}/>
                <Meta label="Version" value={analysis.versionName ?? "Not decoded"}/>
                <Meta label="Min SDK" value={analysis.minSdk ?? "Not decoded"}/>
                <Meta label="Target SDK" value={analysis.targetSdk ?? "Not decoded"}/>
                <Meta label="File Size" value={formatBytes(analysis.size)}/>
                <Meta label="SHA-256" value={analysis.sha256.slice(0,18)+"…"} mono/>
              </div>

              <div className="stat-grid">{stats.map(s=>{const Icon=s.icon;return <div className="stat" key={s.label}><Icon size={18}/><b>{s.value}</b><span>{s.label}</span></div>;})}</div>

              {tab==="Overview" && <Overview analysis={analysis}/>}
              {tab==="Files" && <FilesView files={filteredFiles} query={query} setQuery={setQuery}/>}
              {tab==="Manifest" && <CodePanel title="AndroidManifest.xml" code={analysis.manifestXml ?? "Binary AndroidManifest.xml detected. Browser-only mode intentionally does not pretend to decode binary AXML."}/>}
              {tab==="Permissions" && <ListView title="Permissions" items={analysis.permissions} empty="No permissions decoded in the available manifest representation."/>}
              {tab==="Components" && <Components analysis={analysis}/>}
              {tab==="Code" && <CodeView analysis={analysis}/>}
              {tab==="Resources" && <ResourceView analysis={analysis}/>}
              {tab==="Network" && <NetworkView analysis={analysis}/>}
              {tab==="Security" && <SecurityView analysis={analysis}/>}
              {tab==="Signing" && <SigningView analysis={analysis}/>}
              {tab==="Technology" && <ListView title="Detected technologies" items={analysis.technologies} empty="No known technology signature detected."/>}
              {tab==="Reports" && <Reports analysis={analysis} downloadJSON={downloadJSON}/>}
            </>
          )}
        </section>
      </div>
    </main>
  );
}

function Feature({icon,title,text}:{icon:React.ReactNode,title:string,text:string}) { return <div className="feature"><div>{icon}</div><b>{title}</b><span>{text}</span></div> }
function Meta({label,value,mono}:{label:string,value:string,mono?:boolean}) { return <div className="meta"><span>{label}</span><b className={mono?"mono":""}>{value}</b></div> }
function Overview({analysis}:{analysis:APKAnalysis}) {
  const counts = {high:analysis.findings.filter(x=>x.severity==="high").length,medium:analysis.findings.filter(x=>x.severity==="medium").length,low:analysis.findings.filter(x=>x.severity==="low").length};
  return <div className="overview">
    <div className="panel"><div className="panel-title">Analysis Summary</div><div className="summary-grid"><Summary label="Files" value={analysis.files.length}/><Summary label="Resources" value={analysis.resources.length}/><Summary label="Assets" value={analysis.assets.length}/><Summary label="Native libraries" value={analysis.nativeLibraries.length}/><Summary label="URLs" value={analysis.urls.length}/><Summary label="Domains" value={analysis.domains.length}/></div></div>
    <div className="panel"><div className="panel-title">Security indicators</div><div className="findings-head"><div className="score">{Math.max(0,100-counts.high*20-counts.medium*10-counts.low*3)}<small>/100</small></div><div><b>Evidence-based indicator</b><p>Not a formal vulnerability score. Review each finding and its evidence.</p></div></div>{analysis.findings.length?analysis.findings.map((f,i)=><Finding key={i} f={f}/>):<div className="empty">No indicators were triggered by the included checks.</div>}</div>
    <div className="two"><ListCard title="Technology" items={analysis.technologies}/><ListCard title="Network" items={analysis.domains.slice(0,8)}/></div>
  </div>
}
function Summary({label,value}:{label:string,value:number}) {return <div className="summary"><b>{value}</b><span>{label}</span></div>}
function Finding({f}:{f:APKAnalysis["findings"][number]}) {return <div className="finding"><span className={`dot ${f.severity}`}/><div><b>{f.title}</b><small>{f.evidence}</small></div><em>{f.severity}</em></div>}
function ListCard({title,items}:{title:string,items:string[]}) {return <div className="panel"><div className="panel-title">{title}</div>{items.length?items.map(x=><div className="list-row" key={x}>{x}</div>):<div className="empty">None detected.</div>}</div>}
function ListView({title,items,empty}:{title:string,items:string[],empty:string}) {return <div className="panel full"><div className="panel-title">{title}<span>{items.length}</span></div>{items.length?items.map(x=><div className="list-row" key={x}>{x}</div>):<div className="empty">{empty}</div>}</div>}
function FilesView({files,query,setQuery}:{files:APKAnalysis["files"],query:string,setQuery:(s:string)=>void}) {return <div className="panel full"><div className="panel-title">APK File Explorer <span>{files.length} files</span></div><div className="search"><Search size={15}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search files..."/></div><div className="file-list">{files.map(f=><div className="file-row" key={f.path}>{f.path.includes("/")?<Folder size={15}/>:<FileText size={15}/>}<span>{f.path}</span><small>{formatBytes(f.size)}</small></div>)}</div></div>}
function Components({analysis}:{analysis:APKAnalysis}) {return <div className="three">{(["Activities","Services","Receivers"] as const).map(kind=>{const arr=analysis[kind.toLowerCase() as "activities"|"services"|"receivers"];return <div className="panel" key={kind}><div className="panel-title">{kind}<span>{arr.length}</span></div>{arr.map((x:any)=><div className="component"><b>{x.name}</b><span>{x.exported===null?"exported: unknown":`exported: ${x.exported}`}</span></div>)}</div>})}<div className="panel"><div className="panel-title">Providers<span>{analysis.providers.length}</span></div>{analysis.providers.map(x=><div className="component"><b>{x.name}</b><span>exported: {x.exported ?? "unknown"}</span></div>)}</div></div>}
function CodeView({analysis}:{analysis:APKAnalysis}) {
  const [classFilter, setClassFilter] = useState("");
  const allDexClasses = useMemo(() => {
    return analysis.dexFiles.flatMap(d => (d.classes ?? []).map(c => ({ dex: d.path, name: c })));
  }, [analysis]);
  const filtered = useMemo(() => {
    if (!classFilter.trim()) return allDexClasses.slice(0, 300);
    return allDexClasses.filter(c => c.name.toLowerCase().includes(classFilter.toLowerCase())).slice(0, 300);
  }, [allDexClasses, classFilter]);

  return (
    <div className="panel full">
      <div className="panel-title">DEX Files & Classes <span>{analysis.dexFiles.length} DEX files</span></div>
      <div className="meta-grid" style={{ marginBottom: "1.2rem" }}>
        {analysis.dexFiles.map(x => (
          <div className="dex-card" key={x.path} style={{ margin: 0 }}>
            <Code2 size={20}/>
            <div>
              <b>{x.path}</b>
              <span>{formatBytes(x.size)} · {x.classCount ?? 0} classes · {x.methodCount ?? 0} methods · {x.strings.toLocaleString()} strings</span>
            </div>
          </div>
        ))}
      </div>

      <div className="panel-title" style={{ marginTop: "1rem" }}>
        Compiled Java / Kotlin Classes <span>{allDexClasses.length} parsed classes</span>
      </div>
      <div className="search">
        <Search size={15}/>
        <input value={classFilter} onChange={e => setClassFilter(e.target.value)} placeholder="Filter class names (e.g. com.example.MainActivity)..."/>
      </div>
      <div className="file-list" style={{ maxHeight: "360px", overflowY: "auto" }}>
        {filtered.length ? filtered.map((c, i) => (
          <div className="file-row" key={`${c.dex}-${c.name}-${i}`}>
            <Code2 size={14}/>
            <span>{c.name}</span>
            <small>{c.dex}</small>
          </div>
        )) : <div className="empty">No classes matched your search.</div>}
      </div>
    </div>
  );
}

function ResourceView({analysis}:{analysis:APKAnalysis}) {return <div className="two"><ListView title="Resources" items={analysis.resources} empty="No res/ files found."/><ListView title="Assets" items={analysis.assets} empty="No assets found."/></div>}
function NetworkView({analysis}:{analysis:APKAnalysis}) {return <div className="two"><ListView title="URLs" items={analysis.urls} empty="No HTTP(S) URLs found in scanned DEX strings."/><ListView title="Domains" items={analysis.domains} empty="No domains found."/><ListView title="WebView indicators" items={analysis.webViews} empty="No WebView signature detected."/></div>}
function SecurityView({analysis}:{analysis:APKAnalysis}) {return <div className="panel full"><div className="panel-title">Security Analysis</div>{analysis.findings.length?analysis.findings.map((f,i)=><Finding key={i} f={f}/>):<div className="empty">No indicators triggered.</div>}<div className="notice"><ShieldCheck size={16}/> These are static indicators, not proof of exploitable vulnerabilities. Every result includes evidence from the APK artifacts scanned by this build.</div></div>}

function SigningView({analysis}:{analysis:APKAnalysis}) {
  const cert = analysis.certificate;
  if (!cert) {
    return (
      <div className="panel full">
        <div className="panel-title">Certificate & Signing</div>
        <div className="empty">No valid APK signature (v1 JAR or v2/v3 Signing Block) was detected in this file.</div>
      </div>
    );
  }

  return (
    <div className="panel full">
      <div className="panel-title">Certificate & Signing <span>Scheme: {cert.scheme}</span></div>
      <div className="meta-grid" style={{ marginTop: "1rem" }}>
        <Meta label="Signing Scheme" value={cert.scheme}/>
        <Meta label="Signature Algorithm" value={cert.sigAlg}/>
        <Meta label="Valid From" value={cert.validFrom}/>
        <Meta label="Valid To" value={cert.validTo}/>
        <Meta label="Subject" value={cert.subject}/>
        <Meta label="Issuer" value={cert.issuer}/>
        <Meta label="Serial Number" value={cert.serialNumber} mono/>
        <Meta label="SHA-256 Fingerprint" value={cert.sha256Fingerprint} mono/>
        <Meta label="SHA-1 Fingerprint" value={cert.sha1Fingerprint} mono/>
      </div>
    </div>
  );
}
function Reports({analysis,downloadJSON}:{analysis:APKAnalysis,downloadJSON:()=>void}) {return <div className="panel full"><div className="panel-title">Reports</div><p className="report-text">Export the complete structured analysis currently stored in this browser.</p><button className="primary" onClick={downloadJSON}><FileText size={15}/> Download JSON report</button><div className="notice"><Lock size={16}/> The report is generated from local IndexedDB data. This build does not upload reports to a server.</div></div>}
function CodePanel({title,code}:{title:string,code:string}) {return <div className="panel full"><div className="panel-title">{title}</div><pre className="code">{code}</pre></div>}
function formatBytes(n:number){if(n<1024)return `${n} B`;if(n<1024**2)return `${(n/1024).toFixed(1)} KB`;if(n<1024**3)return `${(n/1024**2).toFixed(2)} MB`;return `${(n/1024**3).toFixed(2)} GB`;}