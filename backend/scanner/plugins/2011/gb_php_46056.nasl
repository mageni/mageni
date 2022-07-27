###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_46056.nasl 10458 2018-07-09 06:47:36Z cfischer $
#
# PHP MySQLi Extension 'set_magic_quotes_runtime' Function Security-Bypass Weakness
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
  script_oid("1.3.6.1.4.1.25623.1.0.103051");
  script_version("$Revision: 10458 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 08:47:36 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2011-01-31 12:59:22 +0100 (Mon, 31 Jan 2011)");
  script_bugtraq_id(46056);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4700");
  script_name("PHP MySQLi Extension 'set_magic_quotes_runtime' Function Security-Bypass Weakness");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46056");
  script_xref(name:"URL", value:"http://bugs.php.net/52221");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net");

  script_tag(name:"impact", value:"Successful exploits will allow attackers to possibly bypass certain
  security protections.");

  script_tag(name:"affected", value:"PHP 5.3.2 and 5.3.3 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"PHP is prone to a security-bypass weakness.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_in_range(version:phpVer, test_version:"5.3.2", test_version2:"5.3.3")) {
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.4");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);