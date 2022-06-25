###############################################################################
# OpenVAS Vulnerability Test
# $Id: nmap_net.nasl 11663 2018-09-28 06:18:46Z cfischer $
#
# Launch Nmap for Network Scanning (nmap_net system)
#
# Authors:
# Henri Doreau <henri.doreau@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104000");
  script_version("$Revision: 11663 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 08:18:46 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-05-31 15:59:37 +0200 (Tue, 31 May 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Launch Nmap for Network Scanning");
  script_category(ACT_SCANNER);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Port scanners");

  # --- Host discovery ---
  script_add_preference(name:"Treat all hosts as online", type:"checkbox", value:"no");
  script_add_preference(name:"Trace hop path to each host", type:"checkbox", value:"no");
  script_add_preference(name:"Disable DNS resolution", type:"checkbox", value:"no");

  # --- Scan techniques ---
  script_add_preference(name:"TCP scanning technique", type:"radio", value:"connect();SYN;ACK;FIN;Window;Maimon;Xmas tree;Null;SCTP Init;SCTP COOKIE_ECHO");
  script_add_preference(name:"Service scan", type:"checkbox", value:"no");
  script_add_preference(name:"RPC port scan", type:"checkbox", value:"no");

  # --- OS Detection ---
  script_add_preference(name:"Identify the remote OS", type:"checkbox", value:"no");
  script_add_preference(name:"Aggressive OS detection", type:"checkbox", value:"no");

  # --- Firewall/IDS evasion ---
  script_add_preference(name:"Fragment IP packets (bypasses firewalls)", type:"checkbox", value:"no");
  script_add_preference(name:"Source port", value:"", type:"entry");

  # --- Timing and performances ---
  script_add_preference(name:"Timing policy", type:"radio", value:"Normal;Insane;Aggressive;Polite;Sneaky;Paranoid");
  script_add_preference(name:"Host Timeout (ms)", value:"", type:"entry");
  script_add_preference(name:"Min RTT Timeout (ms)", value:"", type:"entry");
  script_add_preference(name:"Max RTT Timeout (ms)", value:"", type:"entry");
  script_add_preference(name:"Initial RTT timeout (ms)", value:"", type:"entry");
  script_add_preference(name:"Ports scanned in parallel (min)", value:"", type:"entry");
  script_add_preference(name:"Ports scanned in parallel (max)", value:"", type:"entry");
  script_add_preference(name:"Hosts scanned in parallel (min)", value:"", type:"entry");
  script_add_preference(name:"Hosts scanned in parallel (max)", value:"", type:"entry");
  script_add_preference(name:"Minimum wait between probes (ms)", value:"", type:"entry");

  # --- Targets specification ---
  script_add_preference(name:"Exclude hosts", value:"", type:"entry");

  script_add_preference(name:"File containing XML results", value:"", type:"file");

  script_dependencies("toolcheck.nasl");

  script_mandatory_keys("Tools/Present/nmap5.51");

  script_tag(name:"summary", value:"This script controls the execution of Nmap for network-wide
scanning. Depending on selections made, this may include port scanning, OS
detection, service detection and the execution of NSE tests.");

  exit(0);
}

include("nmap.inc");
include("misc_func.inc");
include("host_details.inc");

if (!defined_func("plugin_run_nmap")) {
    # display("Error: advanced nmap wrapper unavailable. Neither nmap_net nor related NSE wrappers will run.\n");
    exit(2);
}


function report_host_alive() {
    local_var state;

    state = get_kb_item("Host/State");
    if (isnull(state) || "up" >!< state) {
        # Host is dead, mark it as such
        set_kb_item( name:"Host/dead", value:TRUE );
    }
}

function report_open_ports() {
    local_var svc_map, services, svcname, ports, port, portno;

    # map ports to services
    svc_map = make_array();
    services = get_kb_list("Services/*");
    if (!isnull(services)) {
        foreach svc (keys(services)) {
            svcname = split(svc, sep:"/", keep:FALSE);
            svc_map[services[svc]] = svcname[1];
        }
    }

    # report open tcp ports
    ports = get_kb_list("Ports/tcp/*");
    if (!isnull(ports)) {
        foreach portstr (keys(ports)) {
            port = split(portstr, sep:"/", keep:FALSE);

            portno = int(port[2]);
            scanner_add_port(proto:"tcp", port:portno);

            # XXX Corresponding keys are already set by the C plugin
            # XXX register_service(port:portno, proto:svc_map[portno]);
        }
    }

    # report open udp ports
    ports = get_kb_list("Ports/udp/*");
    if (!isnull(ports)) {
        foreach portstr (keys(ports)) {
            port = split(portstr, sep:"/", keep:FALSE);

            portno = int(port[2]);
            scanner_add_port(proto:"udp", port:portno);

            # XXX Corresponding keys are already set by the C plugin
            # XXX register_service(port:portno, proto:svc_map[portno], ipproto:"udp");
        }
    }
}

function report_detected_versions() {
    local_var versions, ver, tokens, proto, port, service, report, cpelist, cpe;

    versions = get_kb_list("Version/*");
    if (!isnull(versions)) {
        foreach ver (keys(versions)) {
            tokens = split(ver, sep:"/", keep:FALSE);
            proto = tokens[1];
            port = tokens[2];

            service = get_kb_item(string("Known/", proto, '/', port));
            # display('Service (Known/', proto, '/', port, '): ', service, '\n');

            report = string('nmap thinks ', service, ' ', versions[ver], ' is running on this port');

            cpelist = get_kb_list('App/' + proto + '/' + port);
            if (!isnull(cpelist)) {
                foreach cpe (cpelist) {
                    report += '\nCPE: ' + cpe + '\n';
                    if ('cpe:/a:' >< cpe) {
                        register_product(cpe:cpe, location:string(port, '/', proto),
                                         nvt:"1.3.6.1.4.1.25623.1.0.104000");
                    } else {
                        register_host_detail(name:"OS", value:cpe);
                    }
                }
            }
            log_message(port:port, proto:proto, data:report);
        }
    }
}

function report_detected_os() {
    local_var os, cpe, report;

    report = '';
    # report OS fingerprint if available
    os = get_kb_item("Host/OS");
    if (!isnull(os)) {
        report += 'Nmap OS fingerprint result: ' + os + '\n\n';
        register_host_detail(name:"OS", value:os);
    }

    # report OS CPEs
    os = get_kb_list("Host/CPE");
    if (!isnull(os)) {
        foreach cpe (os) {
            report += 'CPE: ' + cpe + '\n';
            register_host_detail(name:"OS", value:cpe);
        }
    }

    if (report != '')
        log_message(data:report);
}

function report_tcpip_seqs() {
    local_var ipidseq, tcpseq_index, tcpseq_difficulty, report;

    # report detected evolution of TCP/IP sensitive fields
    ipidseq = get_kb_item("Host/ipidseq");

    if (!isnull(ipidseq)) {
        report = 'Nmap detected IP ID sequence class as: ' + ipidseq + '\n\n';
        log_message(data:report);
    }

    tcpseq_index = get_kb_item("Host/tcp_seq_index");
    tcpseq_difficulty = get_kb_item("Host/tcp_seq_difficulty");

    if (!isnull(tcpseq_index) && !isnull(tcpseq_difficulty)) {
      report = 'Nmap detected a TCP sequence number evolution of ' +
               tcpseq_index + ' with a probability of exploitability estimated as: "' +
               tcpseq_difficulty + '"\n\n';
      security_message(data:report);
    }
}

function report_traceroute() {
    local_var report, dist, i, addr, rtt, host;

    report = 'TTL\t\tRTT\t\tADDRESS\t\tHOST\n';
    dist = get_kb_item("Host/distance");

    if (isnull(dist))
        return;

    for (i = 0; i < dist; i++) {
        addr = get_kb_item("Host/traceroute/hops/" + string(i));
        rtt = get_kb_item("Host/traceroute/hops/" + string(i) + "/rtt");
        host = get_kb_item("Host/traceroute/hops/" + string(i) + "/host");

        if (isnull(addr))
            continue;
        if (isnull(rtt))
            rtt = '...';
        if (isnull(host))
            host = '...';

        report += i + 1 + '\t\t' + rtt + '\t\t' + addr + '\t\t' + host + '\n';
    }

    log_message(data:report);
}


phase = 0;

if (defined_func("scan_phase")) {
  phase = scan_phase();
}

if (phase == 1) {
    # network phase: run the C plugin
    plugin_run_nmap();
} else if (phase == 2) {
    # host phase: read and report results for the current host
    report_host_alive();
    report_open_ports();
    report_detected_versions();
    report_detected_os();
    report_tcpip_seqs();
    report_traceroute();

    set_kb_item(name:"Host/scanned", value:TRUE);
    set_kb_item(name:"Host/scanners/nmap_net", value:TRUE);

} else {
    # There we are in deep trouble...
    # display("Error: network wide scanning unavailable/disabled. Neither nmap_net nor related NSE wrappers will run.\n");
}

exit(0);

