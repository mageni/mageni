# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.108957");
  script_version("2020-10-23T05:50:24+0000");
  script_tag(name:"last_modification", value:"2020-10-23 10:08:30 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-23 05:42:28 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-27615");

  script_name("WordPress Loginizer Plugin < 1.6.4 - Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/loginizer/detected");

  script_tag(name:"summary", value:"The WordPress plugin Loginizer is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A properly crafted username used to login could lead to SQL injection (CVE-2020-27615)

  - If the IP HTTP header was modified to have a null byte it could lead to stored XSS");

  script_tag(name:"impact", value:"- Successful exploitation of this vulnerability would allow a remote attacker
  to execute arbitrary SQL commands on the affected system (CVE-2020-27615)

  - Successful exploitation would allow an attacker to inject arbitrary script code into an affected site");

  script_tag(name:"affected", value:"WordPress Loginizer plugin before version 1.6.4.");

  script_tag(name:"solution", value:"Update to version 1.6.4 or later.");

  script_xref(name:"URL", value:"https://loginizer.com/blog/loginizer-1-6-4-security-fix/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/loginizer/#developers");
  script_xref(name:"URL", value:"https://wpdeeply.com/loginizer-before-1-6-4-sqli-injection/");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/10441");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/2401010/loginizer");

  exit(0);
}

CPE = "cpe:/a:raj_kothari:loginizer";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.6.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.6.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
