###############################################################################
# OpenVAS Vulnerability Test
# $Id: sniff_file_disclosure.nasl 6040 2017-04-27 09:02:38Z teissa $
#
# Snif File Disclosure
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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

# From: J [jay@j-security.co.uk]
# To: full-disclosure@lists.netsys.com
# Subject: Snif 1.2.4 file retrieval bug
# Date: Thursday 27/11/2003 01:02

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11944");
  script_version("$Revision: 6040 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Snif File Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to Snif version 1.2.5 or newer");
  script_tag(name:"summary", value:"It is possible to make the remote host return the content of any world
  readable file by requesting a path outside the bound HTML root directory from the Snif program.");
  script_tag(name:"impact", value:"An attacker may use this flaw to view sensitive files that reside on the
  remote host.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );

  if( egrep( pattern:"snif (1\.[0-1]|1\.1a|1\.2|1\.2\.[1-4])  &copy; 2003 Kai Blankenhorn", string:res ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
