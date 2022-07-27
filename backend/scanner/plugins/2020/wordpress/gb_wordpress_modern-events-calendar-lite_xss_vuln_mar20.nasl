# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113648");
  script_version("2020-03-06T08:08:22+0000");
  script_tag(name:"last_modification", value:"2020-03-06 10:39:50 +0000 (Fri, 06 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-05 11:43:54 +0000 (Thu, 05 Mar 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-9459");

  script_name("WordPress Modern Events Calendar Lite Plugin <= 5.1.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("modern-events-calendar-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin Modern Events Calendar Lite is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote authenticated users can exploit the vulnerability via
  Ajax actions in mec_save_notifications and import_settings.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"WordPress Modern Events Calendar Lite plugin through version 5.1.6.");

  script_tag(name:"solution", value:"Update to version 5.1.7 or later.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/10100");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/02/site-takeover-campaign-exploits-multiple-zero-day-vulnerabilities/");

  exit(0);
}

CPE = "cpe:/a:webnus:modern-events-calendar-lite";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.1.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );