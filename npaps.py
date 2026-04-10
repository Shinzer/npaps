import re
import argparse
from jinja2 import Environment

def parse_nmap_file(file_path):
    port_map = {}
    ssl_audit = []
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] Error: File {file_path} not found.")
        return None, [], 0
        
    hosts = content.split("Nmap scan report for ")
    total_hosts_parsed = 0
    
    for host_data in hosts[1:]:
        lines = host_data.strip().split('\n')
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", lines[0])
        if not ip_match: continue
        ip = ip_match.group(1)
        total_hosts_parsed += 1
        
        # SSL/TLS Logic Parsing
        if "TLSv1.0" in host_data: ssl_audit.append({"ip": ip, "type": "Weak Protocol", "info": "TLSv1.0 Enabled"})
        if "TLSv1.1" in host_data: ssl_audit.append({"ip": ip, "type": "Weak Protocol", "info": "TLSv1.1 Enabled"})
        if "SSLv2" in host_data: ssl_audit.append({"ip": ip, "type": "Vulnerable", "info": "SSLv2 Enabled"})
        if "SSLv3" in host_data: ssl_audit.append({"ip": ip, "type": "Vulnerable", "info": "SSLv3 Enabled"})

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
                
    return dict(sorted(port_map.items(), key=lambda x: int(x[0]))), ssl_audit, total_hosts_parsed

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VAPT Recon Suite | vLfLEqiP</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root { 
            --vapt-dark: #0f172a; 
            --vapt-slate: #1e293b;
            --vapt-crimson: #be123c;
            --vapt-accent: #38bdf8;
            --vapt-bg: #f8fafc;
            --vapt-border: #e2e8f0;
        }
        body { background-color: var(--vapt-bg); color: var(--vapt-dark); padding: 0; font-family: 'Inter', -apple-system, sans-serif; font-size: 0.9rem; }
        
        /* Top Navigation Bar */
        .vapt-navbar { background: var(--vapt-dark); padding: 25px; border-bottom: 4px solid var(--vapt-crimson); color: white; margin-bottom: 30px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
        .vapt-navbar h2 { font-weight: 800; letter-spacing: -1px; margin: 0; }
        .vapt-navbar .stats-pill { background: rgba(255,255,255,0.1); padding: 5px 15px; border-radius: 20px; font-size: 0.8rem; border: 1px solid rgba(255,255,255,0.2); }

        .sticky-controls { position: sticky; top: 0; z-index: 1020; background: white; padding: 15px 0; border-bottom: 1px solid var(--vapt-border); margin-bottom: 25px; }
        
        /* Accordion Styling */
        .accordion-item { border: 1px solid var(--vapt-border); margin-bottom: 10px; border-radius: 8px !important; overflow: hidden; background: white; box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1); }
        .accordion-button { font-weight: 600; color: var(--vapt-slate); background: white; }
        .accordion-button:not(.collapsed) { background: #f1f5f9; color: var(--vapt-crimson); border-bottom: 1px solid var(--vapt-border); }
        
        /* Table Styling */
        .table { margin-bottom: 0; }
        .table thead { background: var(--vapt-slate); color: white; }
        .table-hover tbody tr:hover { background-color: #f1f5f9; }
        
        /* Action Buttons */
        .btn-vapt { background: var(--vapt-crimson); border: none; color: white; font-weight: 600; padding: 8px 20px; border-radius: 6px; transition: 0.2s; }
        .btn-vapt:hover { background: #9f1239; color: white; transform: translateY(-1px); }
        .btn-copy { border: 1px solid var(--vapt-border); background: white; color: var(--vapt-slate); font-weight: 600; font-size: 0.75rem; }
        .btn-copy:hover { border-color: var(--vapt-accent); color: var(--vapt-accent); }

        code { color: var(--vapt-crimson); background: #fff1f2; padding: 2px 6px; border-radius: 4px; font-weight: 500; font-family: 'JetBrains Mono', 'Fira Code', monospace; }
        .port-tag { background: var(--vapt-dark); color: white; padding: 3px 10px; border-radius: 4px; font-weight: bold; margin-right: 15px; }

        /* Audit Section */
        .audit-header { margin-top: 50px; background: white; border-left: 5px solid var(--vapt-crimson); padding: 15px; border-radius: 0 8px 8px 0; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
    </style>
</head>
<body>
    <div class="vapt-navbar text-center">
        <div class="container d-flex justify-content-between align-items-center">
            <h2>NPAPS <span style="color: var(--vapt-accent);">Dashboard</span></h2>
            <div class="d-flex gap-3">
                <span class="stats-pill">Total Targets: {{ total_hosts }}</span>
                <span class="stats-pill">Total Open Ports: {{ data|length }}</span>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="sticky-controls">
            <div class="row align-items-center">
                <div class="col-md-6 d-flex align-items-center">
                    <div class="form-check me-4">
                        <input class="form-check-input" style="margin-left: 2.5px; margin-right: 2.5px;" type="checkbox" id="selectAllToggle" onclick="toggleAll(this)">
                        <label class="form-check-label fw-bold" for="selectAllToggle">Select All</label>
                    </div>
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" id="includeCmdToggle">
                        <label class="form-check-label fw-bold" for="includeCmdToggle">Include Commands</label>
                    </div>
                </div>
                <div class="col-md-6 text-end">
                    <button class="btn btn-vapt btn-sm" style="margin-right: 10px;" id="masterCopy" onclick="copySelected()">Copy Selected</button>
                </div>
            </div>
        </div>

        <div class="accordion" id="portAccordion">
            {% for port, hosts in data.items() %}
            <div class="accordion-item">
                <div class="d-flex align-items-center px-3 py-1">
                    <input type="checkbox" class="port-checkbox form-check-input" data-port="{{ port }}">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse{{ port }}">
                        <span class="port-tag">TCP {{ port }}</span>
                        <span class="text-muted small">{{ hosts|length }} IP Address(es) Identified</span>
                    </button>
                </div>
                
                <div id="collapse{{ port }}" class="accordion-collapse collapse" data-bs-parent="#portAccordion">
                    <div class="accordion-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover align-middle">
                                <thead>
                                    <tr>
                                        <th class="ps-4">IP Address</th>
                                        <th>Service</th>
                                        <th>Suggested Command</th>
                                        <th class="text-center">Copy Command</th>
                                    </tr>
                                </thead>
                                <tbody id="body{{ port }}">
                                    {% for host in hosts %}
                                    <tr data-ip="{{ host.ip }}" data-svc="{{ host.service }}" data-cmd="{{ host.cmd }}">
                                        <td class="ps-4"><strong>{{ host.ip }}</strong></td>
                                        <td><span class="badge border border-dark text-dark text-uppercase">{{ host.service }}</span></td>
                                        <td><code>{{ host.cmd }}</code></td>
                                        <td class="text-center"><button class="btn btn-copy btn-sm" onclick="copyToClipboard('{{ host.cmd }}')">COPY</button></td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>

        {% if ssl_audit %}
        <div class="audit-header d-flex justify-content-between align-items-center">SSL/TLS Audit</h4>
            <button class="btn btn-vapt btn-sm" onclick="copySSL()">Copy SSL Findings</button>
        </div>
        <div class="mt-3 bg-white rounded shadow-sm border">
            <table class="table table-bordered">
                <thead class="table-dark">
                    <tr>
                        <th>Target IP</th>
                        <th>Risk Classification</th>
                        <th>Technical Finding</th>
                    </tr>
                </thead>
                <tbody id="sslTableBody">
                    {% for vuln in ssl_audit %}
                    <tr>
                        <td class="ps-3"><strong>{{ vuln.ip }}</strong></td>
                        <td><span class="badge bg-danger">{{ vuln.type }}</span></td>
                        <td><code>{{ vuln.info }}</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function toggleAll(master) {
            document.querySelectorAll('.port-checkbox').forEach(cb => cb.checked = master.checked);
        }

        function copyToClipboard(text) {
            const el = document.createElement('textarea');
            el.value = text;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
        }

        function copySSL() {
            let sslRows = [];
            document.querySelectorAll('#sslTableBody tr').forEach(row => {
                const ip = row.cells[0].innerText;
                const type = row.cells[1].innerText;
                const info = row.cells[2].innerText;
                sslRows.push(`${ip}\\t${type}\\t${info}`);
            });
            copyToClipboard(sslRows.join('\\n'));
            alert("Hala XSS! Copied to clipboard!");
        }

        function copySelected() {
            const checkboxes = document.querySelectorAll('.port-checkbox:checked');
            const includeCmd = document.getElementById('includeCmdToggle').checked;
            let allRows = [];

            checkboxes.forEach(cb => {
                const port = cb.getAttribute('data-port');
                document.querySelectorAll(`#body${port} tr`).forEach(row => {
                    const ip = row.getAttribute('data-ip');
                    const svc = row.getAttribute('data-svc');
                    const cmd = row.getAttribute('data-cmd');
                    let line = `${ip}\\t${port}\\t${svc}`;
                    if (includeCmd) line += `\\t${cmd}`;
                    allRows.push(line);
                });
            });

            if (allRows.length === 0) { alert("Pili ka ng port muna, tas saka mo icopy to clipboard..."); return; }

            copyToClipboard(allRows.join('\\n'));
            const btn = document.getElementById('masterCopy');
            btn.innerText = "CAPTURED " + allRows.length + " DATA_POINTS";
            setTimeout(() => { btn.innerText = "COPY TO WORKBENCH"; }, 2000);
        }
    </script>
</body>
</html>
"""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-o", "--output", default="vapt_report.html")
    args = parser.parse_args()

    env = Environment(extensions=['jinja2.ext.do'])
    data, ssl_audit, total_hosts = parse_nmap_file(args.file)
    
    if data:
        template = env.from_string(HTML_TEMPLATE)
        html_output = template.render(data=data, ssl_audit=ssl_audit, total_hosts=total_hosts)
        with open(args.output, "w") as f:
            f.write(html_output)
        print(f"[+] VAPT Report Generation Complete: {args.output}")

if __name__ == "__main__":
    main()
