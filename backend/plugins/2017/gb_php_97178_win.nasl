###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_97178_win.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# PHP Server Side Request Forgery Security Bypass Vulnerability (Windows)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108139");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2017-7272");
  script_bugtraq_id(97178);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-18 06:00:00 +0200 (Tue, 18 Apr 2017)");
  script_name("PHP Server Side Request Forgery Security Bypass Vulnerability (Windows)");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://bugs.php.net/74216");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the php_wddx_pop_element
  function in ext/wddx/wddx.c via an inapplicable class name in a wddxPacket XML document,
  leading to mishandling in a wddx_deserialize call.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass security
  restrictions and perform unauthorized actions. This may aid in further attacks.");

  script_tag(name:"affected", value:"PHP versions 7.0.x before 7.0.18 and 7.1.x before 7.1.4.");

  script_tag(name:"solution", value:"Upgrade to PHP version 7.0.18, 7.1.4
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"7.0", test_version2:"7.0.17" ) ) {
  vuln = TRUE;
  fix = "7.0.18";
}

if( vers =~ "^7\.1") {
  if( version_is_less( version:vers, test_version:"7.1.4" ) ) {
    vuln = TRUE;
    fix = "7.1.4";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );