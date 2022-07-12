# OpenVAS Vulnerability Test
# $Id: raptor_detect.nasl 13685 2019-02-15 10:06:52Z cfischer $
# Description: Raptor FW version 6.5 detection
#
# Authors:
# Noam Rathaus
# Holm Diening / SLITE IT-Security (holm.diening@slite.de)
#
# Copyright:
# Copyright (C) 2000 Holm Diening
# Copyright (C) 2001 Holm Diening / SLITE IT-Security (holm.diening@slite.de)
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
  script_oid("1.3.6.1.4.1.25623.1.0.10730");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Raptor FW version 6.5 detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2000 Holm Diening");
  script_family("Firewalls");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Patch httpd / httpd.exe by hand.");

  script_tag(name:"summary", value:"By sending an invalid HTTP request to an
  webserver behind Raptor firewall, the http proxy itself will respond.

  The server banner of Raptor FW version 6.5 is always 'Simple, Secure Web Server 1.1'.");

  script_tag(name:"impact", value:"You should avoid giving an attacker such
  information.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

teststring = string("some invalid request\r\n\r\n");
testpattern = string("Simple, Secure Web Server 1.");

recv = http_send_recv(port:port, data:teststring);
if(testpattern >< recv) {
  report = string("The remote WWW host is very likely behind Raptor FW Version 6.5\n", "You should patch the httpd proxy to return bogus version and stop\n", "the information leak\n");
  security_message(port:port, data:report);
  http_set_is_marked_embedded(port:port);
}
