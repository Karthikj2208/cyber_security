const btn=document.getElementById("analyze");
btn.onclick=async()=>{
 const path=document.getElementById("path").value.trim(); document.getElementById("error").textContent="";
 btn.disabled=true;btn.textContent="Analyzing...";
 try{
  const r=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path})});
  const d=await r.json();if(!r.ok)throw new Error(d.error||"Analysis failed");
  document.getElementById("results").classList.remove("hidden");
  document.getElementById("lines").textContent=d.lines;
  document.getElementById("failed").textContent=d.failed_logins;
  document.getElementById("ips").textContent=d.unique_ips;
  document.getElementById("alerts").textContent=d.alerts.length;
  document.getElementById("rows").innerHTML=d.alerts.map(a=>`<tr><td class="${a.severity.toLowerCase()}">${a.severity}</td><td>${a.type}</td><td>${a.source_ip}</td><td>${a.count}</td><td>${a.message}</td></tr>`).join("")||`<tr><td colspan="5">No alerts detected.</td></tr>`;
 }catch(e){document.getElementById("error").textContent=e.message}
 finally{btn.disabled=false;btn.textContent="Analyze Log"}
};