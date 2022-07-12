# OpenVAS Vulnerability Test
# Description: vqServer administrative port
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
# - solution
# - script id
#
# Copyright:
# Copyright (C) 2005 SecuriTeam
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
  script_version("2020-09-30T10:18:14+0000");
  script_tag(name:"last_modification", value:"2020-10-09 10:01:41 +0000 (Fri, 09 Oct 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("vqServer administrative port");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("gb_vqserver_detect.nasl");
  script_mandatory_keys("vqserver/detected");

  script_tag(name:"summary", value:"vqSoft's vqServer administrative port is open.");

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
  log_message(port:port, data:banner);
}

exit( 0 );
