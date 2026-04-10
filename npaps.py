import re
import argparse
from jinja2 import Environment

def parse_nmap_file(file_path):
    port_map = {}
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] Error: File {file_path} not found.")
        return None, 0
        
    hosts = content.split("Nmap scan report for ")
    total_hosts_parsed = 0
    
    for host_data in hosts[1:]:
        lines = host_data.strip().split('\n')
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", lines[0])
        if not ip_match: continue
        ip = ip_match.group(1)
        total_hosts_parsed += 1
        
        for line in lines:
            match = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
            if match:
                port = match.group(1)
                service = match.group(2)
                
                # Command Logic Generator
                cmd = f"nmap -sC -sV -p {port} {ip}" 
                if port == '21': cmd = f"ftp {ip}"
                elif port == '22': cmd = f"ssh user@{ip}"
                elif port in ['80', '443', '8080']: cmd = f"ffuf -u http://{ip}/FUZZ -w /usr/share/wordlists/dirb/common.txt"
                elif port in ['139', '445']: cmd = f"smbclient -L //{ip} -N"
                elif port == '161': cmd = f"snmpwalk -v2c -c public {ip}"
                elif port == '1433': cmd = f"impacket-mssqlclient -windows-auth {ip}"
                elif port == '3306': cmd = f"mysql -h {ip} -u root"
                elif port == '3389': cmd = f"xfreerdp /v:{ip} /u:admin"
                
                if port not in port_map:
                    port_map[port] = []
                port_map[port].append({"ip": ip, "service": service, "cmd": cmd})
                
    return dict(sorted(port_map.items(), key=lambda x: int(x[0]))), total_hosts_parsed

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>vLfLEqiP -7</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root { 
            --matrix-green: #00ff41; 
            --deep-black: #0d0d0d; 
            --pure-white: #ffffff; 
            --faded-green: #008f11; 
        }
        body { background-color: var(--deep-black); color: var(--pure-white); padding: 20px; font-family: 'Courier New', monospace; font-size: 0.9rem; }
        .scan-header { border: 1px solid var(--faded-green); padding: 15px; margin-bottom: 25px; background: rgba(0,255,65,0.05); }
        .sticky-top-custom { position: sticky; top: 0; z-index: 1020; background-color: var(--deep-black); padding: 15px 0; border-bottom: 1px solid var(--faded-green); }
        .accordion-item { background-color: transparent; border: 1px solid #444; margin-bottom: 5px; overflow: hidden; }
        .accordion-button { background-color: var(--deep-black); color: var(--pure-white); box-shadow: none !important; }
        .accordion-button:not(.collapsed) { background-color: rgba(0,255,65,0.05); color: var(--matrix-green); }
        .accordion-button::after { filter: invert(1); }
        .table-matrix { color: var(--pure-white); --bs-table-bg: transparent; }
        .btn-matrix { background: transparent; border: 1px solid var(--matrix-green); color: var(--matrix-green); font-size: 0.7rem; font-weight: bold; }
        .btn-matrix:hover { background: var(--matrix-green); color: var(--deep-black); }
        .port-checkbox { width: 18px; height: 18px; margin-right: 15px; border: 1px solid var(--matrix-green); background: transparent; cursor: pointer; }
        .port-checkbox:checked { background-color: var(--matrix-green); border-color: var(--matrix-green); }
        code { color: var(--matrix-green); }
        
        .text-muted { color: var(--pure-white) !important; opacity: 1; }
        .text-success { color: var(--matrix-green) !important; }
        
        /* Toggle Switch Styling */
        .form-check-input:checked { background-color: var(--matrix-green); border-color: var(--matrix-green); }
        .form-check-label { cursor: pointer; font-weight: bold; margin-left: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="scan-header text-center">
            <h2 style="color: var(--matrix-green);">NPAPS!</h2>
            <p class="mb-0 text-muted">Di ako marunong mag awk at cut -Tian</p>
            <p class="mb-0 text-muted">Hosts: {{ total_hosts }} | Ports: {{ data|length }}</p>
        </div>

        <div class="sticky-top-custom d-flex justify-content-between align-items-center">
            <div class="d-flex align-items-center">
                <div class="form-check form-switch me-4">
                    <input class="form-check-input" type="checkbox" id="includeCmdToggle">
                    <label class="form-check-label text-success" for="includeCmdToggle">Include Commands on Clipboard?</label>
                </div>
            </div>
            <button class="btn btn-matrix btn-lg" id="masterCopy" onclick="copySelected()">COPY SELECTED FOR SPREADSHEET</button>
        </div>

        <div class="accordion mt-3" id="portAccordion">
            {% for port, hosts in data.items() %}
            <div class="accordion-item">
                <div class="d-flex align-items-center px-3 bg-dark">
                    <input type="checkbox" class="port-checkbox form-check-input" 
                           data-port="{{ port }}">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse{{ port }}">
                        <span class="badge border border-success text-success me-3">PORT {{ port }}</span>
                        <span class="text-muted">{{ hosts|length }} Targets Identified</span>
                    </button>
                </div>
                
                <div id="collapse{{ port }}" class="accordion-collapse collapse" data-bs-parent="#portAccordion">
                    <div class="accordion-body">
                        <table class="table table-matrix table-hover table-sm">
                            <thead><tr><th class="text-white">IP_ADDRESS</th><th class="text-white">SERVICE</th><th class="text-white">SUGGESTED_COMMAND</th><th class="text-white">ACTION</th></tr></thead>
                            <tbody id="body{{ port }}">
                                {% for host in hosts %}
                                <tr data-ip="{{ host.ip }}" data-svc="{{ host.service }}" data-cmd="{{ host.cmd }}">
                                    <td><code>{{ host.ip }}</code></td>
                                    <td><span class="badge border border-white text-white">{{ host.service }}</span></td>
                                    <td><code>{{ host.cmd }}</code></td>
                                    <td><button class="btn btn-matrix btn-sm" onclick="copyToClipboard('{{ host.cmd }}')">COPY CMD</button></td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function copyToClipboard(text) {
            const el = document.createElement('textarea');
            el.value = text;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
        }

        function copySelected() {
            const checkboxes = document.querySelectorAll('.port-checkbox:checked');
            const includeCmd = document.getElementById('includeCmdToggle').checked;
            let allRows = [];

            checkboxes.forEach(cb => {
                const port = cb.getAttribute('data-port');
                const rows = document.querySelectorAll(`#body${port} tr`);
                
                rows.forEach(row => {
                    const ip = row.getAttribute('data-ip');
                    const svc = row.getAttribute('data-svc');
                    const cmd = row.getAttribute('data-cmd');
                    
                    let line = `${ip}\\t${port}\\t${svc}`;
                    if (includeCmd) {
                        line += `\\t${cmd}`;
                    }
                    allRows.push(line);
                });
            });

            if (allRows.length === 0) { alert(">> ERROR: SELECT AT LEAST ONE PORT."); return; }

            copyToClipboard(allRows.join('\\n'));
            const btn = document.getElementById('masterCopy');
            const originalText = btn.innerText;
            btn.innerText = "COPIED " + allRows.length + " ROWS!";
            setTimeout(() => { btn.innerText = originalText; }, 2000);
        }
    </script>
</body>
</html>
"""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-o", "--output", default="output.html")
    args = parser.parse_args()

    env = Environment(extensions=['jinja2.ext.do'])
    data, total_hosts = parse_nmap_file(args.file)
    
    if data:
        template = env.from_string(HTML_TEMPLATE)
        html_output = template.render(data=data, total_hosts=total_hosts)
        with open(args.output, "w") as f:
            f.write(html_output)
        print(f"[+] Tactical Aggregator (v3.3) ready: {args.output}")

if __name__ == "__main__":
    main()

























    ##San kaya gagamitin yung -7?
