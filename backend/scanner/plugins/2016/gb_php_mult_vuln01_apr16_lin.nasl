###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln01_apr16_lin.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# PHP Multiple Vulnerabilities - 01 - Apr16 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807807");
  script_version("$Revision: 12431 $");
  script_cve_id("CVE-2016-3142", "CVE-2016-3141");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-04-22 17:47:06 +0530 (Fri, 22 Apr 2016)");
  script_name("PHP Multiple Vulnerabilities - 01 - Apr16 (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A use-after-free error in wddx.c script in the WDDX extension in PHP

  - An error in the phar_parse_zipfile function in zip.c script in the PHAR
  extension in PHP.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to gain access to potentially sensitive information and
  conduct a denial of service (memory corruption and application crash).");

  script_tag(name:"affected", value:"PHP versions before 5.5.33, and 5.6.x before
  5.6.19 on Linux");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.5.33 or 5.6.19
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=71587");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=71498");
  script_xref(name:"URL", value:"https://secure.php.net/ChangeLog-5.php");

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

if(version_is_less(version:phpVer, test_version:"5.5.33"))
{
  fix = '5.5.33';
  VULN = TRUE;
}

else if(phpVer =~ "^5\.6")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.18"))
  {
    fix = '5.6.19';
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);