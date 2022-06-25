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
  script_oid("1.3.6.1.4.1.25623.1.0.108558");
  script_version("$Revision: 14300 $");
  script_cve_id("CVE-2019-9787");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 08:52:26 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-15 08:35:17 +0100 (Fri, 15 Mar 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("WordPress Multiple Vulnerabilities - March19 (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Wordpress is prone to a Cross Site Request Forgery (CSRF) vulnerability in
  a comment form which leads to HTML injection and cross-site scripting (XSS) attacks.");

  script_tag(name:"impact", value:"Chaining all found vulnerabilities, an attacker might be able to execute remote
  code on the affected system, getting access to the underlying hosting system.");

  script_tag(name:"affected", value:"WordPress 5.1.x prior to 5.1.1, 5.0.x prior to 5.0.4, 4.9.x prior to 4.9.10, 4.8.x prior to 4.8.9,
  4.7.x prior to 4.7.13, 4.6.x prior to 4.6.14, 4.5.x prior to 4.5.17, 4.4.x prior to 4.4.18, 4.3.x prior to 4.3.19, 4.2.x prior to 4.2.23,
  4.1.x prior to 4.1.26, 4.0.x prior to 4.0.26 and 3.9.x prior to 3.9.27.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to 5.1.1, 5.0.4, 4.9.10, 4.8.9, 4.7.13, 4.6.14, 4.5.17, 4.4.18, 4.3.19, 4.2.23,
  4.1.26, 4.0.26, 3.9.27 or any later version.");

  script_xref(name:"URL", value:"https://blog.ripstech.com/2019/wordpress-csrf-to-rce/");
  script_xref(name:"URL", value:"https://github.com/WordPress/WordPress/commit/0292de60ec78c5a44956765189403654fe4d080b");
  script_xref(name:"URL", value:"https://wordpress.org/news/2019/03/wordpress-5-1-1-security-and-maintenance-release/");
  script_xref(name:"URL", value:"https://wordpress.org/support/wordpress-version/version-5-1-1/");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

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

if( vers =~ "^5\.1\." && version_is_less( version:vers, test_version:"5.1.1" ) )
  fix = "5.1.1";

else if( vers =~ "^5\.0\." && version_is_less( version:vers, test_version:"5.0.4" ) )
  fix = "5.0.4";

else if( vers =~ "^4\.9\." && version_is_less( version:vers, test_version:"4.9.10" ) )
  fix = "4.9.10";

else if( vers =~ "^4\.8\." && version_is_less( version:vers, test_version:"4.8.9" ) )
  fix = "4.8.9";

else if( vers =~ "^4\.7\." && version_is_less( version:vers, test_version:"4.7.13" ) )
  fix = "4.7.13";

else if( vers =~ "^4\.6\." && version_is_less( version:vers, test_version:"4.6.14" ) )
  fix = "4.6.14";

else if( vers =~ "^4\.5\." && version_is_less( version:vers, test_version:"4.5.17" ) )
  fix = "4.5.17";

else if( vers =~ "^4\.4\." && version_is_less( version:vers, test_version:"4.4.18" ) )
  fix = "4.4.18";

else if( vers =~ "^4\.3\." && version_is_less( version:vers, test_version:"4.3.19" ) )
  fix = "4.3.19";

else if( vers =~ "^4\.2\." && version_is_less( version:vers, test_version:"4.2.23" ) )
  fix = "4.2.23";

else if( vers =~ "^4\.1\." && version_is_less( version:vers, test_version:"4.1.26" ) )
  fix = "4.1.26";

else if( vers =~ "^4\.0\." && version_is_less( version:vers, test_version:"4.0.26" ) )
  fix = "4.0.26";

else if( version_is_less( version:vers, test_version:"3.9.27" ) )
  fix = "3.9.27";

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:path );
  security_message( port:port, data:report);
  exit( 0 );
}

exit( 99 );