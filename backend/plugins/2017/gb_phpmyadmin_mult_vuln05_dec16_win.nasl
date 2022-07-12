###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_mult_vuln05_dec16_win.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# phpMyAdmin Multiple Security Vulnerabilities - 04 - Dec16 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108132");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-10 12:18:02 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2016-9866", "CVE-2016-9865", "CVE-2016-9864", "CVE-2016-9861", "CVE-2016-9860",
                "CVE-2016-9859", "CVE-2016-9858", "CVE-2016-9857", "CVE-2016-9856", "CVE-2016-9850",
                "CVE-2016-9849", "CVE-2016-9848", "CVE-2016-9847");
  script_name("phpMyAdmin Multiple Security Vulnerabilities - 04 - Dec16 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"phpMyAdmin 4.6.x prior to 4.6.5, 4.4.x prior to 4.4.15.9, and 4.0.x prior to 4.0.10.18.");

  script_tag(name:"solution", value:"Update to version 4.6.5, 4.4.15.9 or 4.0.10.18.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^4\.0\." ) {
  if( version_is_less( version:vers, test_version:"4.0.10.18" ) ) {
    vuln = TRUE;
    fix = "4.0.10.18";
  }
}

if( vers =~ "^4\.4\." ) {
  if( version_is_less( version:vers, test_version:"4.4.15.9" ) ) {
    vuln = TRUE;
    fix = "4.4.15.9";
  }
}

if( vers =~ "^4\.6\." ) {
  if( version_is_less( version:vers, test_version:"4.6.5" ) ) {
    vuln = TRUE;
    fix = "4.6.5";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
