# OpenVAS Vulnerability Test
# $Id: DDI_Cabletron_Web_View.nasl 13685 2019-02-15 10:06:52Z cfischer $
# Description: Cabletron Web View Administrative Access
#
# Authors:
# Forrest Rae
#
# Copyright:
# Copyright (C) 2002 Digital Defense Incorporated
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
  script_oid("1.3.6.1.4.1.25623.1.0.10962");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cabletron Web View Administrative Access");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Digital Defense Incorporated");
  script_family("Privilege escalation");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Depending on the location of the switch, it might
  be advisable to restrict access to the web server by IP address or disable the web
  server completely.");

  script_tag(name:"summary", value:"This host is a Cabletron switch and is running
  Cabletron WebView. This web software provides a graphical, real-time representation of
  the front panel on the switch. This graphic, along with additionally defined areas of the
  browser interface, allow you to interactively configure the switch, monitor its status, and
  view statistical information. An attacker can use this to gain information about this host.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

req = http_get(item:"/chassis/config/GeneralChassisConfig.html", port:port);
res = http_send_recv(port:port, data:req);

if("Chassis Configuration" >< res){
  security_message(port:port);
  http_set_is_marked_embedded(port:port);
}

exit(0);