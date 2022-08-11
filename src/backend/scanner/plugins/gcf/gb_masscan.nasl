###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_masscan.nasl 10411 2018-07-05 10:15:10Z cfischer $
#
# masscan (NASL wrapper)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105924");
  script_version("$Revision: 10411 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2014-10-07 11:55:49 +0700 (Tue, 07 Oct 2014)");
  script_name("masscan (NASL wrapper)");
  script_category(ACT_SCANNER);
  script_family("Port scanners");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("toolcheck.nasl", "ping_host.nasl");
  script_mandatory_keys("Tools/Present/masscan");

  script_tag(name:"summary", value:'This plugin runs masscan (Mass IP port scanner) to find open ports.');

  script_xref(name:"URL", value:"https://github.com/robertdavidgraham/masscan");

  script_add_preference(name:"Scan rate (packets/sec) :", value:"100", type:"entry");
  script_add_preference(name:"Source port :", value:"", type:"entry");
  script_add_preference(name:"TCP port :", value:"1-1024", type:"entry");
  script_add_preference(name:"UDP port :", value:"53,137,138", type:"entry");

  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

ip = get_host_ip();
esc_ip = "";
len = strlen(ip);
for (i=0; i<len; i++) {
  if (ip[i] == '.') {
    esc_ip = strcat(esc_ip, "\.");
  }
  else {
    esc_ip = strcat(esc_ip, ip[i]);
  }
}

i = 0;
argv[i++] = "masscan";

argv[i++] = "-n";	# no DNS resolution
argv[i++] = "-Pn";	# treat host as alive
argv[i++] = "-oG";	# grepable output
argv[i++] = "-";

scan_rate = script_get_preference("Scan rate (packets/sec) :");
if (scan_rate !~ '^[0-9]+$') {
  scan_rate = "100";
}
argv[i++] = "--rate";
argv[i++] = scan_rate;

p = script_get_preference("TCP port :");
if (p) {
  argv[i++] = "-p";
  argv[i++] = p;
}

p = script_get_preference("UDP port :");
if (p) {
  argv[i++] = "-pU:";
  argv[i++] = p;
}

p = script_get_preference("Source port :");
if (p =~ '^[0-9]+$') {
  argv[i++] = "-g";
  argv[i++] = p;
}

argv[i++] = ip;

scanner_status(current:0, total:65525);
res = pread(cmd:"masscan", argv:argv, cd:1);

if (!res) {
  exit(0);		# error
}

if (egrep(string:res, pattern:'^# +Ports scanned: +TCP\\(65535;')) {
  full_scan = 1;
} else {
  full_scan = 0;
}

res = egrep(string:res, pattern:"Host: +" + esc_ip + " ");
if (!res) {
  mark_dead = get_kb_item("/ping_host/mark_dead");
  if (mark_dead >< "yes") {
    set_kb_item( name:"Host/dead", value:TRUE );
  }
  exit(0);
}

res = ereg_replace(pattern:'Host: +[0-9.]+ [()\t]+Ports: +', string:res, replace:"");

scanned = 0;
udp_scanned = 0;

foreach blob (split(res, keep:0)) {
  v = eregmatch(string:blob, icase:1,
       pattern: "^(Host: .*:)? *([0-9]+)/([^/]+)/([^/]+)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/?");
  if (!isnull(v)) {
    port = v[2];
    proto = v[4];
    scanner_add_port(proto:proto, port:port);
    scanned++;
    if (proto == "udp") {
      udp_scanned++;
    }
  }
}

if (scanned) {
  set_kb_item(name:"Host/scanned", value:TRUE);
  set_kb_item(name:"Host/scanners/masscan", value:TRUE);
}

if (udp_scanned) {
  set_kb_item(name:"Host/udp_scanned", value:TRUE);
}

if (full_scan) {
  set_kb_item(name:"Host/full_scan", value:TRUE);
}

scanner_status(current:65535, total:65535);
