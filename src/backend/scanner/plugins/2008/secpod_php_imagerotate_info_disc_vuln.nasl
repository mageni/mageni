###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_imagerotate_info_disc_vuln.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# PHP 'imageRotate()' Memory Information Disclosure Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900186");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-5498");
  script_bugtraq_id(33002);
  script_name("PHP 'imageRotate()' Memory Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Dec/1021494.html");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/33002.php");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/33002-2.php");

  script_tag(name:"impact", value:"Successful exploitation could let the attacker read the contents of arbitrary
  memory locations through a crafted value for an indexed image.");

  script_tag(name:"affected", value:"PHP version 5.x to 5.2.8 on all running platform.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of bgd_color or clrBack
  argument in imageRotate function.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.2.9 or later.");

  script_tag(name:"summary", value:"The host is running PHP and is prone to Memory Information
  Disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) )
  exit( 0 );

if( version_in_range( version:phpVer, test_version:"5.0", test_version2:"5.2.8" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"5.2.9" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );