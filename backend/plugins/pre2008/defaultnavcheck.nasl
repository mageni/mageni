###############################################################################
# OpenVAS Vulnerability Test
# $Id: defaultnavcheck.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# DefaultNav checker
#
# Authors:
# Hemil Shah
#
# Copyright:
# Copyright (C) 2000 - 2004 Net-Square Solutions Pvt Ltd.
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
###############################################################################

# Desc: This script will check for the DefaultNav vuln working on remote web server.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12247");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("DefaultNav checker");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Net-Square Solutions Pvt Ltd.");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.nextgenss.com/advisories/defaultnav.txt");

  script_tag(name:"summary", value:"This plugin checks for DefaultNav vulnerabilities on the remote web server

  See the references for more information.");

  script_tag(name:"solution", value:"Disable the DefaultNav functionality within the web server configuration");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # Broken

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
host = http_host_name(dont_add_port:TRUE);
if(http_get_no404_string(port:port, host:host))exit(0);

dirs[0] = "/%24DefaultNav";
dirs[1] = "/%24defaultNav";
dirs[2] = "/%24%64*efaultNav";
dirs[3] = "/%24%44*efaultnav";
dirs[4] = "/$defaultNav";
dirs[5] = "/$DefaultNav";
dirs[6] = "/$%64efaultNav";
dirs[7] = "/$%44efaultNav";

report = string("The DefaultNav request is enabled on the remote host\n");

nsfName = "/names.nsf";

for (i=0; dirs[i]; i++) {
  res = http_keepalive_send_recv(port:port, data:http_get(item:string(nsfName, dirs[i], "/"), port:port));
  if ( res == NULL ) exit(0);
  if(ereg(pattern:"HTTP/1.[01] 200", string:res) ) {
    report += string("specifically, the request for ", nsfName, dirs[i], "/ is\n");
    report += string("capable of remotely compromising the integrity of the system.");
    log_message(port:port, data:report);
    exit(0);
  }
}