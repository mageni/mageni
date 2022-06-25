###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_30649.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# PHP Multiple Buffer Overflow Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.100583");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)");
  script_bugtraq_id(30649);
  script_cve_id("CVE-2008-3659", "CVE-2008-3658");
  script_name("PHP Multiple Buffer Overflow Vulnerabilities");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30649");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.2.8");
  script_xref(name:"URL", value:"http://www.php.net/archive/2008.php#id2008-08-07-1");
  script_xref(name:"URL", value:"http://www.php.net/");
  script_xref(name:"URL", value:"http://support.avaya.com/elmodocs2/security/ASA-2009-161.htm");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to execute arbitrary code in
  the context of applications using the vulnerable PHP functions. This
  may result in a compromise of the underlying system. Failed attempts
  may lead to a denial-of-service condition.");

  script_tag(name:"affected", value:"Versions prior to PHP 4.4.9 and PHP 5.2.8 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"PHP is prone to multiple buffer-overflow vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^4\.4" ) {
  if( version_is_less( version:vers, test_version:"4.4.9" ) ) {
    vuln = TRUE;
    fix = "4.4.9";
  }
} else if( vers =~ "^5\.2" ) {
  if( version_is_less( version:vers, test_version:"5.2.8" ) ) {
    vuln = TRUE;
    fix = "5.2.8";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );