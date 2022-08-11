###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln01_jan15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# PHP Multiple Vulnerabilities - 01 - Jan15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805409");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-3670", "CVE-2014-3669", "CVE-2014-3668");
  script_bugtraq_id(70611, 70665, 70666);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-06 17:18:33 +0530 (Tue, 06 Jan 2015)");
  script_name("PHP Multiple Vulnerabilities - 01 - Jan15");

  script_tag(name:"summary", value:"This host is installed with PHP and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The exif_ifd_make_value function in exif.c in the EXIF extension in PHP
    operates on floating-point arrays incorrectly.

  - Integer overflow in the object_custom function in ext/standard/var
    _unserializer.c in PHP.

  - Buffer overflow in the date_from_ISO8601 function in the mkgmtime
    implementation in libxmlrpc/xmlrpc.c in the XMLRPC extension in PHP.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service or possibly execute arbitrary code
  via different crafted dimensions.");

  script_tag(name:"affected", value:"PHP versions 5.4.x before 5.4.34, 5.5.x
  before 5.5.18, and 5.6.x before 5.6.2");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.4.34 or 5.5.18
  or 5.6.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=68044");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(phpVer =~ "^5\.[4-6]")
{
  if(version_in_range(version:phpVer, test_version:"5.4.0", test_version2:"5.4.33")||
     version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.17")||
     version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.1")) {
    report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.4.34/5.5.18/5.6.2");
    security_message(data:report, port:phpPort);
    exit(0);
  }
}

exit(99);
