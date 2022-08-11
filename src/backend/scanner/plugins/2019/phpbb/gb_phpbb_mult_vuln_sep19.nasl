# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112640");
  script_version("2019-09-23T13:33:30+0000");
  script_tag(name:"last_modification", value:"2019-09-23 13:33:30 +0000 (Mon, 23 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-23 12:32:45 +0000 (Mon, 23 Sep 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2019-16107", "CVE-2019-16108", "CVE-2019-13376");
  script_name("phpBB 3.2.x < 3.2.8 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpBB/installed");

  script_tag(name:"summary", value:"phpBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Previous versions of phpBB did not properly enforce form tokens on two separate pages
  which could have been used to trick users into carrying out unwanted actions. (CVE-2019-16107, CVE-2019-13376)

  - Improper validation of BBCode parameters allowed modifying the style attribute
  and injecting arbitrary CSS into the page. (CVE-2019-16108)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  trick users into carrying out unwanted actions or to inject arbitrary CSS into an affected page.");

  script_tag(name:"affected", value:"phpBB version 3.2.x before 3.2.8.");

  script_tag(name:"solution", value:"Update to version 3.2.8 or later.");

  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?f=14&t=2523271");
  script_xref(name:"URL", value:"https://tracker.phpbb.com/browse/PHPBB3-16067?filter=15090");

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

if( vers =~ "^3\.2\." ) {
  if( version_is_less( version:vers, test_version:"3.2.8" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.8", install_path:path );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
