###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_zend_mult_dos_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# PHP Zend and GD Multiple Denial of Service Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801586");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2010-4697", "CVE-2010-4698");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("PHP Zend and GD Multiple Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://bugs.php.net/52879");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to crash the affected
  application, denying service to legitimate users.");

  script_tag(name:"affected", value:"PHP version prior to 5.2.15 and 5.3.x before 5.3.4");

  script_tag(name:"insight", value:"The flaws are due to:

  - An use-after-free error in the 'Zend' engine, which allows remote attackers
    to cause a denial of service.

  - A stack-based buffer overflow in the 'GD' extension, which allows attackers
    to cause a denial of service.");

  script_tag(name:"solution", value:"Upgrade to PHP 5.3.5 or later");

  script_tag(name:"summary", value:"This host is running PHP and is prone to multiple denial of
  service vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/downloads.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less(version:phpVer, test_version:"5.2.15") ||
   version_in_range(version:phpVer, test_version:"5.3", test_version2:"5.3.3")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.2.15/5.3.5");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);