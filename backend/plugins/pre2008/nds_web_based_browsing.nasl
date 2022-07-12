# OpenVAS Vulnerability Test
# Description: Novell Web Server NDS Tree Browsing
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10739");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(484);
  script_cve_id("CVE-1999-1020");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Novell Web Server NDS Tree Browsing");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/securitynews/5XP0L1555W.html");

  script_tag(name:"solution", value:"Configure your Novell Web Server to block access to this CGI,
  or delete it if you do not use it.");

  script_tag(name:"summary", value:"The Novell Web Server default ndsobj.nlm CGI (LCGI) was
  detected. This CGI allows browsing of the NDS Tree without any need for authentication.

  Gaining access to the NDS Tree reveals sensitive information to an attacker.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir(make_list("/lcgi", "/lcgi-bin", "/LCGI", "/apage/lcgi-bin")) {

  req = http_get(item:dir, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    continue;

  if("Available NDS Trees" >< res) {
    report = report_vuln_url(port:port, url:dir);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);