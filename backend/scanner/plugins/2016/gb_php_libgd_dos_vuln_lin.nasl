###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_libgd_dos_vuln_lin.nasl 11811 2018-10-10 09:55:00Z asteins $
#
# PHP 'libgd' Denial of Service Vulnerability (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809338");
  script_version("$Revision: 11811 $");
  script_cve_id("CVE-2016-7568");
  script_bugtraq_id(93184);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 11:55:00 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-03 12:09:46 +0530 (Mon, 03 Oct 2016)");
  script_name("PHP 'libgd' Denial of Service Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an integer overflow
  in the gdImageWebpCtx function in gd_webp.c in the GD Graphics Library.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service, or possibly have unspecified
  other impact.");

  script_tag(name:"affected", value:"PHP versions 5.x through 5.6.26 and 7.0.x through 7.0.11 on Linux");

  script_tag(name:"solution", value:"Update to PHP version 5.6.27 or 7.0.12.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q3/639");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=73003");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://www.php.net");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

## Issue resolved in 5.6.27 and 7.0.12, both released on Oct 13, 2016
if(version_is_less_equal(version:phpVer, test_version:"5.6.26")
   || version_in_range(version:phpVer, test_version:"7.0", test_version2:"7.0.11"))
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.6.27/7.0.12");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
