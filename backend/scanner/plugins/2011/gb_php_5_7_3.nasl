###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_5_7_3.nasl 10472 2018-07-10 05:32:43Z cfischer $
#
# PHP crypt() returns only the salt for MD5
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103225");
  script_version("$Revision: 10472 $");
  script_cve_id("CVE-2011-3189");
  script_tag(name:"last_modification", value:"$Date: 2018-07-10 07:32:43 +0200 (Tue, 10 Jul 2018) $");
  script_tag(name:"creation_date", value:"2011-08-25 15:23:29 +0200 (Thu, 25 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("PHP crypt() returns only the salt for MD5");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.h-online.com/open/news/item/PHP-users-warned-not-to-upgrade-to-5-3-7-1327427.html");
  script_xref(name:"URL", value:"http://www.php.net/archive/2011.php#id2011-08-22-1");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.3.8");

  script_tag(name:"affected", value:"PHP 5.3.7 is vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"PHP 5.3.7, if crypt()is executed with MD5 salts, the return value conists of the
  salt only.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_equal(version:phpVer, test_version:"5.3.7")) {
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.8");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);