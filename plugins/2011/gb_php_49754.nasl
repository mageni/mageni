###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_49754.nasl 10458 2018-07-09 06:47:36Z cfischer $
#
# PHP 'is_a()' Function Remote File Include Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.103296");
  script_version("$Revision: 10458 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 08:47:36 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2011-10-12 15:33:11 +0200 (Wed, 12 Oct 2011)");
  script_bugtraq_id(49754);
  script_cve_id("CVE-2011-3379");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP 'is_a()' Function Remote File Include Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49754");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=55475");
  script_xref(name:"URL", value:"http://www.php.net");
  script_xref(name:"URL", value:"http://www.byte.nl/blog/2011/09/23/security-bug-in-is_a-function-in-php-5-3-7-5-3-8/");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to compromise PHP
  applications using the affected function. This may also result in a
  compromise of the underlying system. Other attacks are also possible.");

  script_tag(name:"affected", value:"PHP 5.3.7 and 5.3.8 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"PHP is prone to a remote file-include vulnerability because it
  fails to properly implement the 'is_a()' function.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_equal(version:phpVer, test_version:"5.3.7") ||
   version_is_equal(version:phpVer, test_version:"5.3.8")) {
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.9");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);