###############################################################################
# OpenVAS Vulnerability Test
# $Id: portbunny.nasl 11886 2018-10-12 13:48:53Z cfischer $
#
# Use portbunny as scanner
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
#
# Copyright:
# Copyright (c) 2008 Vlatko Kosturjak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

# TODO:
# - report back banners grabbed

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80002");
  script_version("$Revision: 11886 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:48:53 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2008-08-31 23:34:05 +0200 (Sun, 31 Aug 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("portbunny (NASL wrapper)");
  script_category(ACT_SCANNER);
  script_copyright("This script is Copyright (C) 2008 Vlatko Kosturjak");
  script_family("Port scanners");
  script_add_preference(name:"Wait longer for triggers to return", type:"checkbox", value:"no");
  script_dependencies("toolcheck.nasl", "ping_host.nasl");
  script_mandatory_keys("Tools/Present/portbunny");

  script_tag(name:"summary", value:"This plugin runs portbunny scan to find open ports.

  Portbunny is (Linux only) kernel module port scanner suitable for large internal portscans.
  This is experimental plugin, use with care.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

ip = get_host_ip();
esc_ip = ""; l = strlen(ip);
for (i = 0; i < l; i ++)
  if (ip[i] == '.')
    esc_ip = strcat(esc_ip, "\.");
  else
    esc_ip = strcat(esc_ip, ip[i]);

i = 0;
argv[i++] = "portbunny";
argv[i++] = "-u";

p = script_get_preference("Wait longer for triggers to return");
if ( p) argv[i++] = "-w";

argv[i++] = ip;
pr = get_preference("port_range");
if (! pr) pr = "1-65535";
argv[i++] = "-p";
argv[i++] = pr;

res = pread(cmd: "portbunny", argv: argv, cd: 1, nice: 5);

# debug
# display("\n====DEBUG===\n");
# display(res);
# display("\n====DEBUG===\n");

# IP_ADDRESS:PORT:TYPE:FULL_BANNER
# 127.0.0.1     53      OPEN            domain
# 127.0.0.1     80      OPEN            http

n_ports = 0;

foreach line(split(res))
{
  v = eregmatch(string: line, pattern: '^'+esc_ip+'[ \t]*([0-9]+)[ \t]*([A-Z]+)[ \t]*([A-Za-z0-9]*)');
# debug
# display (":");
# if (isnull(v)) display ("null:"+esc_ip);
# else display (v[1]+":"+v[2]+":"+v[3]);
# display ("\n");
  if (! isnull(v) && v[2] == "OPEN")
  {
    n_ports++;
    port = v[1];
    proto = "tcp";
    scanner_add_port(proto: proto, port: port);
  }
}

if (n_ports == 0)
{
  security_message(port:0, proto:"tcp",data:"Host does not have any open TCP port");
}

set_kb_item(name: "Host/scanned", value: TRUE);
set_kb_item(name: 'Host/scanners/portbunny', value: TRUE);
if (pr == '1-65535')
  set_kb_item(name: "Host/full_scan", value: TRUE);

scanner_status(current: 65535, total: 65535);

exit (0);
