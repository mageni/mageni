###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_dos_vuln_aug17_lin.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# PHP Denial of Service Vulnerability - Aug17 (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.811409");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2017-11362");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-01 10:20:01 +0530 (Tue, 01 Aug 2017)");
  script_name("PHP Denial of Service Vulnerability - Aug17 (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to
  'ext/intl/msgformat/msgformat_parse.c' script does not restrict the locale length.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (stack-based buffer overflow and
  application crash) or possibly have unspecified impact.");

  script_tag(name:"affected", value:"PHP versions 7.x before 7.0.21 and 7.1.x
  before 7.1.7");

  script_tag(name:"solution", value:"Upgrade to PHP version 7.0.21, or 7.1.7
  or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(phpport = get_app_port(cpe:CPE))){
  exit(0);
}

if(! vers = get_app_version(cpe:CPE, port:phpport)){
  exit(0);
}

if (vers =~ "^7\.0")
{
  if(version_is_less(version:vers, test_version:"7.0.21")){
    fix = "7.0.21";
  }
}

else if(vers =~ "^7\.1")
{
  if(version_is_less(version:vers, test_version:"7.1.7")){
    fix = "7.1.7";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(port:phpport, data:report);
  exit(0);
}
exit(99);
