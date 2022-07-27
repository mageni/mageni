###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lightspeed_40815.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# LiteSpeed Web Server Source Code Information Disclosure Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100744");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-08-05 13:46:20 +0200 (Thu, 05 Aug 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-2333");
  script_bugtraq_id(40815);
  script_name("LiteSpeed Web Server Source Code Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("LiteSpeed/banner");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40815");
  script_xref(name:"URL", value:"http://www.litespeedtech.com/latest/litespeed-web-server-4.0.15-released.html");
  script_xref(name:"URL", value:"http://www.litespeedtech.com");

  script_tag(name:"summary", value:"LiteSpeed Web Server is prone to a vulnerability that lets attackers
  access source code files.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to retrieve certain files
  from the vulnerable computer in the context of the webserver process.
  Information obtained may aid in further attacks.");

  script_tag(name:"affected", value:"LiteSpeed Web Server versions prior to 4.0.15 are affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
if( ! banner || "LiteSpeed" >!< banner ) exit( 0 );
host = http_host_name( dont_add_port:TRUE );

phps = http_get_kb_file_extensions( port:port, host:host, ext:"php" );
if( ! isnull( phps ) ) {
  phps = make_list( phps );
} else {
  phps = make_list( "/index.php" );
}

foreach php( phps ) {

  x++;
  url = php + "\x00.txt";

  if( buf = http_vuln_check( port:port, url:url, pattern:"<\?(php)?", check_header:TRUE ) ) {
    if( "Content-Type: text/plain" >< buf ) {
      if( ! http_vuln_check( port:port, url:php, pattern:"<\?(php)?" ) ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
  if( x >= 3 )
    exit( 0 );
}

exit( 99 );