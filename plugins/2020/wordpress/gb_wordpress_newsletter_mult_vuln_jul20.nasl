# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112795");
  script_version("2020-08-04T08:47:27+0000");
  script_tag(name:"last_modification", value:"2020-08-04 10:39:08 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-04 08:28:00 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Newsletter Plugin < 6.8.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("newsletter/detected");

  script_tag(name:"summary", value:"The WordPress plugin Newsletter is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Authenticated reflected cross-site-scripting (XSS)

  - PHP Object Injection");

  script_tag(name:"impact", value:"Successful exploitation would decode and execute malicious JavaScript in the victim's browser
  or execute arbitrary code, upload files, or perform other tactics that could lead to site takeover.");

  script_tag(name:"affected", value:"WordPress Newsletter plugin before version 6.8.2.");

  script_tag(name:"solution", value:"Update to version 6.8.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/newsletter/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/08/newsletter-plugin-vulnerabilities-affect-over-300000-sites/");

  exit(0);
}

CPE = "cpe:/a:thenewsletterplugin:newsletter";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "6.8.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.8.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
