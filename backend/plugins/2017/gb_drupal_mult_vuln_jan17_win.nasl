###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_mult_vuln_jan17_win.nasl 12021 2018-10-22 14:54:51Z mmartin $
#
# Drupal Multiple Vulnerabilities Jan17 (Windows)
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

CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108100");
  script_version("$Revision: 12021 $");
  script_cve_id("CVE-2017-6377", "CVE-2017-6379", "CVE-2017-6381");
  script_bugtraq_id(96919);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 16:54:51 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-17 11:54:37 +0100 (Fri, 17 Mar 2017)");
  script_name("Drupal Multiple Vulnerabilities Jan17 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.drupal.org/SA-2017-001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96919");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Editor module incorrectly checks access to inline private files.

  - Some admin paths were not protected with a CSRF token.

  - A 3rd party development library including with Drupal 8 development
  dependencies is vulnerable to remote code execution.");

  script_tag(name:"impact", value:"An attacker can exploit these issues
  to bypass certain security restrictions, perform unauthorized actions,
  and execute arbitrary code. Failed exploit attempts may result in a
  denial of service condition.");

  script_tag(name:"affected", value:"Drupal core 8.x versions prior to 8.2.7");

  script_tag(name:"solution", value:"Upgrade to version 8.2.7 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port, version_regex:"^[0-9]\.[0-9]+" ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"8.0", test_version2:"8.2.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.2.7" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
