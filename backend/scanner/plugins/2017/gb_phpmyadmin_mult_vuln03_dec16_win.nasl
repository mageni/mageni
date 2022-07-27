###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_mult_vuln03_dec16_win.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# phpMyAdmin Multiple Security Vulnerabilities - 02 - Dec16 (Windows)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108128");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-10 12:18:02 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2016-6633", "CVE-2016-6632", "CVE-2016-6631", "CVE-2016-6630", "CVE-2016-6629",
                "CVE-2016-6628", "CVE-2016-6627", "CVE-2016-6626", "CVE-2016-6625", "CVE-2016-6624",
                "CVE-2016-6623", "CVE-2016-6622", "CVE-2016-6620", "CVE-2016-6619", "CVE-2016-6618",
                "CVE-2016-6614", "CVE-2016-6613", "CVE-2016-6612", "CVE-2016-6611", "CVE-2016-6610",
                "CVE-2016-6609", "CVE-2016-6607", "CVE-2016-6606");
  script_name("phpMyAdmin Multiple Security Vulnerabilities - 02 - Dec16 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"phpMyAdmin 4.6.x prior to 4.6.4, 4.4.x prior to 4.4.15.8, and 4.0.x prior to 4.0.10.17.");

  script_tag(name:"solution", value:"Update to version 4.6.4, 4.4.15.8 or 4.0.10.17.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^4\.0\." ) {
  if( version_is_less( version:vers, test_version:"4.0.10.17" ) ) {
    vuln = TRUE;
    fix = "4.0.10.17";
  }
}

if( vers =~ "^4\.4\." ) {
  if( version_is_less( version:vers, test_version:"4.4.15.8" ) ) {
    vuln = TRUE;
    fix = "4.4.15.8";
  }
}

if( vers =~ "^4\.6\." ) {
  if( version_is_less( version:vers, test_version:"4.6.4" ) ) {
    vuln = TRUE;
    fix = "4.6.4";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
