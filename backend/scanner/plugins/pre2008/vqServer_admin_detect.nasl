# OpenVAS Vulnerability Test
# $Id: vqServer_admin_detect.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: vqServer administrative port
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
#	- solution
#	- script id
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10354");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1610);
  script_cve_id("CVE-2000-0766");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("vqServer administrative port");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
  script_family("Service detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("vqServer/banner");

  script_xref(name:"URL", value:"http://www.securiteam.com/windowsntfocus/Some_Web_servers_are_still_vulnerable_to_the_dotdotdot_vulnerability.html");

  script_tag(name:"solution", value:"Close this port for outside access.");

  script_tag(name:"summary", value:"vqSoft's vqServer administrative port is open. Brute force guessing of the
  username/password is possible, and a bug in versions 1.9.9 and below allows configuration file retrieval remotely.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_port_for_service(default:9090, proto:"vqServer-admin");
banner = http_get_cache( item:"/", port:port );

if( "Server: vqServer" >< banner && "WWW-Authenticate: Basic realm=/" >< banner ) {
  res = strstr(banner, "Server: ");
  sub = strstr(res, string("\n"));
  res = res - sub;
  res = res - "Server: ";
  res = res - "\n";

  banner = string("vqServer version is : ");
  banner = banner + res;
  security_message(port:port, data:banner);
}

exit( 0 );