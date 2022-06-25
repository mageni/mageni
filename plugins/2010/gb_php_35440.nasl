###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_35440.nasl 10459 2018-07-09 07:41:24Z cfischer $
#
# PHP 'exif_read_data()' JPEG Image Processing Denial Of Service Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100581");
  script_version("$Revision: 10459 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 09:41:24 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)");
  script_bugtraq_id(35440);
  script_cve_id("CVE-2009-2687");
  script_name("PHP 'exif_read_data()' JPEG Image Processing Denial Of Service Vulnerability");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35440");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_10.php");
  script_xref(name:"URL", value:"http://www.php.net/");
  script_xref(name:"URL", value:"http://lists.debian.org/debian-security-announce/2009/msg00263.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-08/0339.html");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100072880");

  script_tag(name:"impact", value:"Successful exploits may allow remote attackers to cause denial-of-
  service conditions in applications that use the vulnerable function.");

  script_tag(name:"affected", value:"Versions prior to PHP 5.2.10 are affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"PHP is prone to a denial-of-service vulnerability in its
  exif_read_data()' function.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^5\.2" ) {
  if( version_is_less( version:vers, test_version:"5.2.10" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.10" );
    security_message( data:report, port:port );
    exit( 0 );
  }
}

exit( 99 );
