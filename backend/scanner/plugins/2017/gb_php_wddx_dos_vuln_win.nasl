###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_wddx_dos_vuln_win.nasl 11959 2018-10-18 10:33:40Z mmartin $
#
# PHP 'WDDX Deserialization' Denial of Service Vulnerability - (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811485");
  script_version("$Revision: 11959 $");
  script_cve_id("CVE-2017-11143");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:33:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-13 14:48:21 +0530 (Thu, 13 Jul 2017)");
  script_name("PHP 'WDDX Deserialization' Denial of Service Vulnerability - (Windows)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an invalid free error for
  an empty boolean element in ext/wddx/wddx.c script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers inject XML for deserialization to crash the PHP interpreter.");

  script_tag(name:"affected", value:"PHP versions before 5.6.31.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.6.31
  or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

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

if(version_is_less(version:vers, test_version:"5.6.31"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.6.31");
  security_message(port:phpport, data:report);
  exit(0);
}
exit(99);