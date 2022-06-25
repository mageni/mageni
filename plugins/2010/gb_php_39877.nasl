###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_39877.nasl 10459 2018-07-09 07:41:24Z cfischer $
#
# PHP 'php_dechunk()' HTTP Chunked Encoding Integer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100617");
  script_version("$Revision: 10459 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 09:41:24 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-05-04 12:32:13 +0200 (Tue, 04 May 2010)");
  script_bugtraq_id(39877);
  script_cve_id("CVE-2010-1866");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP 'php_dechunk()' HTTP Chunked Encoding Integer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39877");
  script_xref(name:"URL", value:"http://php-security.org/2010/05/02/mops-2010-003-php-dechunk-filter-signed-comparison-vulnerability/index.html");
  script_xref(name:"URL", value:"http://www.php.net");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code in the
  context of the PHP process. Failed exploit attempts will result in a
  denial-of-service condition.");

  script_tag(name:"affected", value:"PHP 5.3.0 through 5.3.2 are vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"PHP is prone to a remote integer-overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"5.3", test_version2:"5.3.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.3.3" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );