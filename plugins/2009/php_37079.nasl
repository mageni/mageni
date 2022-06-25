###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_37079.nasl 10459 2018-07-09 07:41:24Z cfischer $
#
# PHP Versions Prior to 5.3.1 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100359");
  script_version("$Revision: 10459 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 09:41:24 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2009-11-23 18:01:08 +0100 (Mon, 23 Nov 2009)");
  script_bugtraq_id(37079);
  script_cve_id("CVE-2009-3559", "CVE-2009-4017");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP Versions Prior to 5.3.1 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37079");
  script_xref(name:"URL", value:"http://securityreason.com/securityalert/6601");
  script_xref(name:"URL", value:"http://securityreason.com/securityalert/6600");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_3_1.php");
  script_xref(name:"URL", value:"http://www.php.net/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2009/Nov/228");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507982");

  script_tag(name:"impact", value:"Some of these issues may be exploited to bypass security restrictions
  and create arbitrary files or cause denial-of-service conditions. The
  impact of the other issues has not been specified.");

  script_tag(name:"affected", value:"These issues affect PHP versions prior to 5.3.1.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"PHP is prone to multiple security vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.3.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.3.2" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );