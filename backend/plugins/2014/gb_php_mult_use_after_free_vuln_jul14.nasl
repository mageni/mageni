###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_use_after_free_vuln_jul14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# PHP Multiple Use-After-Free Vulnerabilities - Jul14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804682");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-4698", "CVE-2014-4670");
  script_bugtraq_id(68511, 68513);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-07-18 14:56:10 +0530 (Fri, 18 Jul 2014)");
  script_name("PHP Multiple Use-After-Free Vulnerabilities - Jul14");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone to multiple use-after-free
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to an use-after-free error related to SPL iterators
  and ArrayIterators.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
  service attacks or possibly have some other unspecified impact.");

  script_tag(name:"affected", value:"PHP version 5.x through 5.5.14");

  script_tag(name:"solution", value:"Apply the updates/patches from the referenced links.

  *****
  NOTE: Ignore this warning if above mentioned patch is installed.
  *****");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56800");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67539");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67538");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=patch;h=df78c48354f376cf419d7a97f88ca07d572f00fb");

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=patch;h=22882a9d89712ff2b6ebc20a689a89452bba4dcd");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(phpVer =~ "^5\.5"){
  if(version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.14")){
    report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.5.15");
    security_message(data:report, port:phpPort);
    exit(0);
  }
}

exit(99);