###############################################################################
# OpenVAS Vulnerability Test
# $Id: compaq_wbem_detect.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# Compaq WBEM Server Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10746");
  script_version("$Revision: 10908 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Compaq WBEM Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("Service detection");
  # nb: Don't add a dependency to http_version.nasl or gb_get_http_banner.nasl to avoid cyclic dependency to embedded_web_server_detect.nasl
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 2301);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable the Anonymous access to Compaq WBEM web server, or
  block the web server's port number on your Firewall.");
  script_tag(name:"summary", value:"We detected the remote web server to be a Compaq WBEM server.
  This web server enables attackers to gather sensitive information on
  the remote host, especially if anonymous access has been enabled.");
  script_tag(name:"insight", value:"Sensitive information includes: Platform name and version (including
  service packs), installed hotfixes, Running services, installed Drivers,
  boot.ini content, registry settings, NetBIOS name, system root directory,
  administrator full name, CPU type, CPU speed, ROM versions and revisions,
  memory size, sever recovery settings, and more.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:2301 );

buf = get_http_banner( port:port );

if( ! buf ) exit( 0 );

if( egrep( pattern:"^Server: CompaqHTTPServer/", string:buf ) ) {

  mod_buf = strstr( buf, "Server: CompaqHTTPServer/" );
  mod_buf = mod_buf - "Server: CompaqHTTPServer/";
  subbuf = strstr( mod_buf, string( "\n" ) );
  mod_buf = mod_buf - subbuf;
  version = mod_buf;

  wbem_version = "false";
  if( buf >< "var VersionCheck = " ) {
    mod_buf = strstr( buf, "var VersionCheck = " );
    mod_buf = mod_buf - string( "var VersionCheck = " );
    mod_buf = mod_buf - raw_string( 0x22 );
    subbuf = strstr( mod_buf, raw_string( 0x22 ) );
    mod_buf = mod_buf - subbuf;
    wbem_version = mod_buf;
  }

  buf = "Remote Compaq HTTP server version is: ";
  buf = buf + version;
  if( ! ( wbem_version == "false" ) ) {
    buf = string( buf, "\nCompaq WBEM server version: " );
    buf = buf + wbem_version;
  }
  log_message( data:buf, port:port );
}

exit( 0 );
