# OpenVAS Vulnerability Test
# Description: Aventail ASAP detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.17583");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-05-05T09:44:01+0000");
  script_tag(name:"last_modification", value:"2020-05-06 11:41:12 +0000 (Wed, 06 May 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Aventail ASAP detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports(8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Filter incoming traffic to this port.");

  script_tag(name:"summary", value:"The remote host seems to be an Aventail SSL VPN appliance,
  connections are allowed to the web console management.

  Letting attackers know that you are using this software will help
  them to focus their attack or will make them change their strategy.

  In addition to this, an attacker may attempt to set up a brute force attack
  to log into the remote interface.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");

port = 8443;
if(!get_port_state(port))
  exit(0);

url = "/console/login.do";
req = http_get(item:url, port:port);
rep = http_send_recv(data:req, port:port);
if(!rep)
  exit(0);

#<title>ASAP Management Console Login</title>
if ("<title>ASAP Management Console Login</title>" >< rep) {
  report = http_report_vuln_url(port:port, url:url);
  log_message(port:port, data:report);
  exit(0);
}

exit(99);
