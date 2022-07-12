###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_22862.nasl 10459 2018-07-09 07:41:24Z cfischer $
#
# PHP Shared Memory Functions Resource Verification Arbitrary Code Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100605");
  script_version("$Revision: 10459 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 09:41:24 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)");
  script_bugtraq_id(22862);
  script_cve_id("CVE-2007-1376");
  script_name("PHP Shared Memory Functions Resource Verification Arbitrary Code Execution Vulnerability");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22862");
  script_xref(name:"URL", value:"http://www.php-security.org/MOPB/MOPB-15-2007.html");
  script_xref(name:"URL", value:"http://www.php.net");
  script_xref(name:"URL", value:"http://lists.suse.com/archive/suse-security-announce/2007-May/0007.html");

  script_tag(name:"impact", value:"An attacker may exploit this issue to execute arbitrary code within
  the context of the affected webserver. The attacker may also gain access to RSA keys
  of the SSL certificate.");

  script_tag(name:"affected", value:"This issue affects PHP 4 versions prior to 4.4.5 and PHP 5 versions
  prior to 5.2.1.");

  script_tag(name:"solution", value:"The vendor released versions 4.4.5 and 5.2.1 to address this issue.
  Please see the references for more information.");

  script_tag(name:"summary", value:"PHP shared memory functions (shmop)are prone to an arbitrary-code-
  execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^4\.4" ) {
  if( version_is_less( version:vers, test_version:"4.4.5" ) ) {
    vuln = TRUE;
    fix = "4.4.5";
  }
} else if( vers =~ "^5\.2" ) {
  if( version_is_less( version:vers, test_version:"5.2.1" ) ) {
    vuln = TRUE;
    fix = "5.2.1";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );