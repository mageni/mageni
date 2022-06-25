# OpenVAS Vulnerability Test
# $Id: cp-firewall-webauth.nasl 6040 2017-04-27 09:02:38Z teissa $
# Description: CheckPoint Firewall-1 Web Authentication Detection
#
# Authors:
# Yoav Goldberg <yoavg@securiteam.com>
#
# Copyright:
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
  script_oid("1.3.6.1.4.1.25623.1.0.10676");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CheckPoint Firewall-1 Web Authentication Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Firewalls");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 900);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"If you do not use this service, disable it");

  script_tag(name:"summary", value:"A Firewall-1 web server is running on this port and serves web
  authentication requests.");

  script_tag(name:"impact", value:"This service allows remote attackers to gather usernames and passwords
  through a brute force attack.");

  script_tag(name:"insight", value:"Older versions of the Firewall-1 product allowed verifying usernames
  prior to checking their passwords, allowing attackers to easily bruteforce a valid list of usernames.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:900);

re = http_get_cache(item:"/", port:port);
if("Authentication Form" >< re && "Client Authentication Remote" >< re && "FireWall-1 message" >< re) {
  security_message(port);
  exit(0);
}

exit(99);