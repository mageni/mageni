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
  script_oid("1.3.6.1.4.1.25623.1.0.113627");
  script_version("2020-01-21T15:40:22+0000");
  script_tag(name:"last_modification", value:"2020-01-21 15:40:22 +0000 (Tue, 21 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-21 15:30:23 +0000 (Tue, 21 Jan 2020)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2020-7106", "CVE-2020-7237");

  script_name("Cacti <= 1.2.8 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Stored XSS vulnerability in data_sources.php, color_templates_item.php,
    graphs.php, graph_items.php, lib/api_automation.php, user_admin.php
    and user_group_admin.php, as demonstrated by the description parameter
    in data_sources.php (a raw string from the database that is displayed
    by $header to trigger the XSS).

  - Remote Code Execution (by privileged users) via shell metacharacters
    in the Performance Boost Debug Log field of poller_automation.php.
    OS commands are executed when a new poller cycle begins. The attacker
    must be authenticated and must have access to modify the Performance Settings.");

  script_tag(name:"impact", value:"Successful exploitation would have effects ranging from the attacker
  injection arbitrary HTML and JavaScript into the site to the attacker
  gaining full control over the target system.");

  script_tag(name:"affected", value:"Cacti through version 1.2.8.");

  script_tag(name:"solution", value:"No known solution is available as of 21st January, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00014.html");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/3191");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/3201");

  exit(0);
}

CPE = "cpe:/a:cacti:cacti";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.2.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
