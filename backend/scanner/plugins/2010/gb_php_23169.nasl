###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_23169.nasl 10459 2018-07-09 07:41:24Z cfischer $
#
# PHP Zip_Entry_Read() Integer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100601");
  script_version("$Revision: 10459 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 09:41:24 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)");
  script_bugtraq_id(23169);
  script_cve_id("CVE-2007-1777");
  script_name("PHP Zip_Entry_Read() Integer Overflow Vulnerability");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23169");
  script_xref(name:"URL", value:"http://www.php-security.org/MOPB/MOPB-35-2007.html");
  script_xref(name:"URL", value:"http://www.php.net/");

  script_tag(name:"impact", value:"Exploiting this issue may allow attackers to execute arbitrary machine
  code in the context of the affected application. Failed exploit
  attempts will likely result in a denial-of-service condition.");

  script_tag(name:"affected", value:"This issue affects versions prior to PHP 4.4.5.");

  script_tag(name:"solution", value:"Reports indicate that PHP 4.4.5 addresses this issue. Please contact
  the vendor for more information.");

  script_tag(name:"summary", value:"PHP is prone to an integer-overflow vulnerability because it
  fails to ensure that integer values aren't overrun. Attackers
  may exploit this issue to cause a heap-based buffer overflow.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"4.4.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.4.5" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );