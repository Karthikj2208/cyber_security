async function refresh(){
  const s=await fetch("/api/status").then(r=>r.json());
  for(const k of ["packets","alerts","critical","high"]) document.getElementById(k).textContent=s[k];
  document.getElementById("top").textContent=s.top_alert;
  const total=Math.max(1,s.alerts);
  document.getElementById("bc").style.width=Math.min(100,s.critical/total*100)+"%";
  document.getElementById("bh").style.width=Math.min(100,s.high/total*100)+"%";
  document.getElementById("bi").style.width=Math.min(100,s.info/total*100)+"%";

  const logs=await fetch("/api/logs?limit=80").then(r=>r.json());
  document.getElementById("log").innerHTML=logs.map(x=>{
    const sev=x.severity.toLowerCase();
    return `<tr>
      <td>${new Date(x.timestamp).toLocaleTimeString()}</td>
      <td class="sev ${sev}">${x.severity}</td>
      <td>${x.type}</td>
      <td>${x.source_ip}</td>
      <td>${x.destination_ip}:${x.destination_port}</td>
      <td>${x.message}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="6">No alerts yet. Generate demo traffic to test the IDS.</td></tr>`;
}
document.getElementById("demo").addEventListener("click",async()=>{
  const btn=document.getElementById("demo"); btn.disabled=true; btn.textContent="Generating...";
  await fetch("/api/scan-demo",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({count:30})});
  await refresh(); btn.disabled=false; btn.textContent="Generate Demo Traffic";
});
refresh(); setInterval(refresh,3000);
