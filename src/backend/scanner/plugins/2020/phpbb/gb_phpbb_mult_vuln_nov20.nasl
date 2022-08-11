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

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117035");
  script_version("2020-11-16T13:02:17+0000");
  script_tag(name:"last_modification", value:"2020-11-17 11:07:05 +0000 (Tue, 17 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-16 12:45:31 +0000 (Mon, 16 Nov 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("phpBB < 3.2.11 / 3.3.x < 3.3.2 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_mandatory_keys("phpBB/installed");

  script_tag(name:"summary", value:"phpBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Invalid conversion of HTML entities when stripping BBCode (SECURITY-264)

  - Reduce verbosity of jabber output in ACP (SECURITY-265)");

  script_tag(name:"affected", value:"phpBB < 3.2.11 and 3.3.x < 3.3.2.");

  script_tag(name:"solution", value:"Update to version 3.2.11, 3.3.2 or later.");

  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?f=14&t=2573416");
  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?f=14&t=2573411");
  script_xref(name:"URL", value:"http://tracker.phpbb.com/browse/SECURITY-264");
  script_xref(name:"URL", value:"http://tracker.phpbb.com/browse/SECURITY-265");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"3.2.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.11", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
} else if( version_in_range( version:vers, test_version:"3.3.0", test_version2:"3.3.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.3.2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
