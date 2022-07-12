# OpenVAS Vulnerability Test
# Description: ISS deployment manager detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.17585");

  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ISS deployment manager detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports(3994);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Filter incoming traffic to this port.");

  script_tag(name:"summary", value:"The remote host appears to run ISS deployment manager, connections are
  allowed to the web interface to remote install various SiteProtector
  components.");

  script_tag(name:"impact", value:"Letting attackers know that you are using this software will help them
  to focus their attack or will make them change their strategy.

  In addition to this, an attacker may attempt to set up a brute force attack
  to log into the remote interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = 3994;
if(!get_port_state(port))
  exit(0);

url = "/deploymentmanager/index.jsp";
req = http_get(item:url, port:port);
res = http_send_recv(data:req, port:port);
if(!res)
  exit(0);

if("<title>SiteProtector</title>" >< res && egrep(pattern:"Welcome to SiteProtector Deployment Manager", string:res)) {
  report = report_vuln_url(port:port, url:url);
  log_message(port:port, data:report);
}

exit(0);