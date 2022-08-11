###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln01_aug16_lin.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# PHP Multiple Vulnerabilities - 01 - Aug16 (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808788");
  script_version("$Revision: 12431 $");
  script_cve_id("CVE-2016-5773", "CVE-2016-5772", "CVE-2016-5769", "CVE-2016-5768",
                "CVE-2016-5766", "CVE-2016-5767");
  script_bugtraq_id(91397, 91398, 91399, 91396, 91395);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-17 12:07:10 +0530 (Wed, 17 Aug 2016)");
  script_name("PHP Multiple Vulnerabilities - 01 - Aug16 (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The 'php_zip.c' script in the zip extension improperly interacts with the
    unserialize implementation and garbage collection.

  - The php_wddx_process_data function in 'wddx.c' script in the WDDX extension
    mishandled data in a wddx_deserialize call.

  - The multiple integer overflows in 'mcrypt.c' script in the mcrypt extension.

  - The double free vulnerability in the '_php_mb_regex_ereg_replace_exec'
    function in 'php_mbregex.c' script in the mbstring extension.

  - An integer overflow in the '_gd2GetHeader' function in 'gd_gd2.c' script in
    the GD Graphics Library.

  - An integer overflow in the 'gdImageCreate' function in 'gd.c' script in the
    GD Graphics Library.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (buffer overflow and application
  crash) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"PHP versions prior to 5.5.37, 5.6.x before
  5.6.23, and 7.x before 7.0.8 on Linux");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.5.37, or 5.6.23,
  or 7.0.8, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less(version:phpVer, test_version:"5.5.37"))
{
  fix = '5.5.37';
  VULN = TRUE;
}

else if(phpVer =~ "^5\.6")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.22"))
  {
    fix = '5.6.23';
    VULN = TRUE;
  }
}

else if(phpVer =~ "^7\.0")
{
  if(version_in_range(version:phpVer, test_version:"7.0", test_version2:"7.0.7"))
  {
    fix = '7.0.8';
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