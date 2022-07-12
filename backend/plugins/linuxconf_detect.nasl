###############################################################################
# OpenVAS Vulnerability Test
# $Id: linuxconf_detect.nasl 10121 2018-06-07 12:44:05Z cfischer $
#
# LinuxConf grants network access
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Modified by Renaud Deraison <deraison@cvs.nessus.org>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10135");
  script_version("$Revision: 10121 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-07 14:44:05 +0200 (Thu, 07 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2000-0017");
  script_name("LinuxConf grants network access");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
  script_family("Service detection");
  # nb: Don't add a dependency to http_version.nasl or gb_get_http_banner.nasl to avoid cyclic dependency to embedded_web_server_detect.nasl
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/linuxconf", 98);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/exploits/Linuxconf_contains_remotely_exploitable_buffer_overflow.html");

  script_tag(name:"solution", value:"Disable Linuxconf access from the network by
  using a firewall, if you do not need Linuxconf use the Linuxconf utility (command
  line or XWindows based version) to disable it.

  See additional information regarding the dangers of keeping this port open at the listed reference");

  script_tag(name:"summary", value:"Linuxconf is running (Linuxconf is a sophisticated administration
  tool for Linux) and is granting network access at least to the host Scanner is running onto.");

  script_tag(name:"insight", value:"LinuxConf is suspected to contain various buffer overflows,
  so you should not let allow networking access to anyone.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item( "Services/linuxconf" );
if( ! port ) port = 98;
if( ! get_port_state( port ) ) exit( 0 );

banner = http_get_cache( item:"/", port:port );

if( "Server: linuxconf" >< banner ) {

  resultrecv = strstr( banner, "Server: " );
  resultsub  = strstr( resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "Server: ";
  resultrecv = resultrecv - "\n";

  banner = "Linuxconf version is : ";
  banner = banner + resultrecv;
  security_message( port:port, data:banner );
  exit( 0 );
}

exit( 99 );