###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln_dec09.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# PHP Multiple Vulnerabilities - Dec09
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801060");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-04 14:17:59 +0100 (Fri, 04 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4018", "CVE-2009-2626");
  script_bugtraq_id(37138, 36009);
  script_name("PHP Multiple Vulnerabilities - Dec09");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37482");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=49026");
  script_xref(name:"URL", value:"http://securityreason.com/achievement_securityalert/65");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/11/23/15");

  script_tag(name:"summary", value:"This host is running PHP and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Error in 'proc_open()' function in 'ext/standard/proc_open.c' that does not
  enforce the 'safe_mode_allowed_env_vars' and 'safe_mode_protected_env_vars'
  directives, which allows attackers to execute programs with an arbitrary
  environment via the env parameter.

  - Error in 'zend_restore_ini_entry_cb()' function in 'zend_ini.c', which
  allows attackers to obtain sensitive information.");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to bypass certain
  security restrictions and cause denial of service.");

  script_tag(name:"affected", value:"PHP version 5.2.10 and prior. PHP version 5.3.x before 5.3.1");

  script_tag(name:"solution", value:"Upgrade to version 5.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"5.2.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.11" );
  security_message( port:port, data:report );
  exit( 0 );
} else if( vers =~ "^5\.3" ) {
  if( version_is_less( version:vers, test_version:"5.3.1" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"5.3.1" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );