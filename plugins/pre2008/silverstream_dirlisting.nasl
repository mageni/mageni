# OpenVAS Vulnerability Test
# Description: SilverStream directory listing
#
# Authors:
# Tor Houghton, but I looked at "htdig" by
# Renaud Deraison <deraison@cvs.nessus.org>
# modifications by rd:
#	- pattern read is different
#	- request /SilverStream not /SilverStream/Pages
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added links to the Bugtraq message archive
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
  script_oid("1.3.6.1.4.1.25623.1.0.10846");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SilverStream directory listing");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Tor Houghton");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/101/144786");

  script_tag(name:"solution", value:"Reconfigure the server so that others
  cannot view directory listings.");

  script_tag(name:"summary", value:"SilverStream directory listings are enabled.");

  script_tag(name:"impact", value:"An attacker may use this problem to gain more
  knowledge on this server and possibly to get files you would want to hide.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = "/SilverStream";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

if((egrep(pattern:"<html><head><title>.*SilverStream.*</title>", string:res)) && ("/Pages" >< res)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);