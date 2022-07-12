###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_dir_traversal_vuln_lin.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# PHP Directory Traversal Vulnerability - Jul16 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808617");
  script_version("$Revision: 14181 $");
  script_cve_id("CVE-2014-9767", "CVE-2015-6834", "CVE-2015-6835", "CVE-2015-6837",
                "CVE-2015-6838");
  script_bugtraq_id(76652, 76649, 76733, 76734, 76738);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)");
  script_name("PHP Directory Traversal Vulnerability - Jul16 (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to Directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An error in the 'ZipArchive::extractTo' function in
    'ext/zip/php_zip.c' script.

  - The xsl_ext_function_php function in ext/xsl/xsltprocessor.c when libxml2
    is used, does not consider the possibility of a NULL valuePop return value
    before proceeding with a free operation after the principal argument loop.

  - Improper handling of multiple php_var_unserialize calls.

  - Multiple use-after-free vulnerabilities.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow remote
  attackers to read arbitrary empty directories, also to cause a denial of service.");

  script_tag(name:"affected", value:"PHP versions prior to 5.4.45, 5.5.x before
  5.5.29, and 5.6.x before 5.6.13 on Linux");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.4.45, or 5.5.29,
  or 5.6.13, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/03/16/20");

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

if(version_is_less(version:phpVer, test_version:"5.4.45"))
{
  fix = '5.4.45';
  VULN = TRUE;
}

else if(phpVer =~ "^5\.5")
{
  if(version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.28"))
  {
    fix = '5.5.29';
    VULN = TRUE;
  }
}

else if(phpVer =~ "^5\.6")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.12"))
  {
    fix = '5.6.13';
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