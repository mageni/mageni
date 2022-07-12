# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112638");
  script_version("2019-09-09T08:37:22+0000");
  script_tag(name:"last_modification", value:"2019-09-09 08:37:22 +0000 (Mon, 09 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-09 08:20:00 +0000 (Mon, 09 Sep 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("WordPress Multiple Vulnerabilities - September19 (Linux)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Wordpress is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - a cross-site scripting (XSS) vulnerability found in post previews by contributors and a cross-site scripting vulnerability in stored comments

  - an issue where validation and sanitization of a URL could lead to an open redirect

  - reflected cross-site scripting during media uploads

  - a vulnerability for cross-site scripting (XSS) in shortcode previews

  - a case where reflected cross-site scripting could be found in the dashboard

  - an issue with URL sanitization that can lead to cross-site scripting (XSS) attacks.");

  script_tag(name:"affected", value:"WordPress 5.2.x before 5.2.3, 5.1.x before 5.1.2, 5.0.x before 5.0.6, 4.9.x before 4.9.11, 4.8.x before 4.8.10,
  4.7.x before 4.7.14, 4.6.x before 4.6.15, 4.5.x before 4.5.18, 4.4.x before 4.4.19, 4.3.x before 4.3.20, 4.2.x before 4.2.24, 4.1.x before 4.1.27,
  4.0.x before 4.0.27, 3.9.x before 3.9.28, 3.8.x before 3.8.30 and all previous versions before 3.7.30.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to 5.2.3, 5.1.2, 5.0.6, 4.9.11, 4.8.10, 4.7.14, 4.6.15, 4.5.18, 4.4.19, 4.3.20, 4.2.24,
  4.1.27, 4.0.27, 3.9.28, 3.8.30 or 3.7.30 respectively.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( vers =~ "^5\.2\." && version_is_less( version:vers, test_version:"5.2.3" ) )
  fix = "5.2.3";

else if( vers =~ "^5\.1\." && version_is_less( version:vers, test_version:"5.1.2" ) )
  fix = "5.1.2";

else if( vers =~ "^5\.0\." && version_is_less( version:vers, test_version:"5.0.6" ) )
  fix = "5.0.6";

else if( vers =~ "^4\.9\." && version_is_less( version:vers, test_version:"4.9.11" ) )
  fix = "4.9.11";

else if( vers =~ "^4\.8\." && version_is_less( version:vers, test_version:"4.8.10" ) )
  fix = "4.8.10";

else if( vers =~ "^4\.7\." && version_is_less( version:vers, test_version:"4.7.14" ) )
  fix = "4.7.14";

else if( vers =~ "^4\.6\." && version_is_less( version:vers, test_version:"4.6.15" ) )
  fix = "4.6.15";

else if( vers =~ "^4\.5\." && version_is_less( version:vers, test_version:"4.5.18" ) )
  fix = "4.5.18";

else if( vers =~ "^4\.4\." && version_is_less( version:vers, test_version:"4.4.19" ) )
  fix = "4.4.19";

else if( vers =~ "^4\.3\." && version_is_less( version:vers, test_version:"4.3.20" ) )
  fix = "4.3.20";

else if( vers =~ "^4\.2\." && version_is_less( version:vers, test_version:"4.2.24" ) )
  fix = "4.2.24";

else if( vers =~ "^4\.1\." && version_is_less( version:vers, test_version:"4.1.27" ) )
  fix = "4.1.27";

else if( vers =~ "^4\.0\." && version_is_less( version:vers, test_version:"4.0.27" ) )
  fix = "4.0.27";

else if( vers =~ "^3\.9\." && version_is_less( version:vers, test_version:"3.9.28" ) )
  fix = "3.9.28";

else if( vers =~ "^3\.8\." && version_is_less( version:vers, test_version:"3.8.30" ) )
  fix = "3.8.30";

else if( version_is_less( version:vers, test_version:"3.7.30" ) )
  fix = "3.7.30";

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:path );
  security_message( port:port, data:report);
  exit( 0 );
}

exit( 99 );
