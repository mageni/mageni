# OpenVAS Vulnerability Test
# $Id: silverstream_database.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: SilverStream database structure
#
# Authors:
# Tor Houghton, but I looked at "htdig" by
# Renaud Deraison <deraison@cvs.nessus.org>
# Changes by rd:
# - phrasing in the report
# - pattern read
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (C) 2002 Tor Houghton
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
  script_oid("1.3.6.1.4.1.25623.1.0.10847");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SilverStream database structure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Tor Houghton");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/101/144786");

  script_tag(name:"solution", value:"Reconfigure the server so that others
  cannot view database structure.");

  script_tag(name:"summary", value:"It is possible to download the remote SilverStream database
  structure by requesting :

  http://www.example.com/SilverStream/Meta/Tables/?access-mode=text");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain more knowledge about
  this host.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = string("/SilverStream/Meta/Tables/?access-mode=text");
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(res && "_DBProduct" >< res) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);