###############################################################################
# OpenVAS Vulnerability Test
#
# WorldClient for MDaemon Server Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Currently no testing scripts for WorldClient vulnerabilities.  Added
# notes of the current list of WorldClient vulnerabilities
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.10745");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2000-0660");
  script_bugtraq_id(1462, 2478, 4687, 4689, 823);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WorldClient for MDaemon Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("WDaemon/banner");
  script_require_ports("Services/www", 3000);

  script_xref(name:"URL", value:"http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeam&words=WorldClient");

  script_tag(name:"solution", value:"Make sure all usernames and passwords are adequately long and
  that only authorized networks have access to this web server's port number
  (block the web server's port number on your firewall).");

  script_tag(name:"summary", value:"We detected the remote web server is
  running WorldClient for MDaemon. This web server enables attackers
  with the proper username and password combination to access locally
  stored mailboxes.

  In addition, earlier versions of WorldClient suffer from buffer overflow
  vulnerabilities, and web traversal problems (if those are found the Risk
  factor is higher).");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:3000 );
banner = get_http_banner( port:port );
if( banner && egrep( pattern:"^Server: WDaemon/", string:banner ) ) {

  log_message( port:port );

  buf = strstr( banner, "WDaemon/" );
  buf = banner - "WDaemon/";
  subbuf = strstr( buf, string("\r\n" ) );
  buf = buf - subbuf;
  version = buf;

  buf = "Remote WorldClient server version is: ";
  buf = buf + version;
  if( version < "4" ) {
    # I'm wondering if this should not be in another plugin (rd)
    report = string("This version of WorldClient contains serious security vulnerabilities.\n", "It is advisable that you upgrade to the latest version." );
    security_message( data:report, port:port );
    exit( 0 );
  }
}

exit( 99 );