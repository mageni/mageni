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
  script_oid("1.3.6.1.4.1.25623.1.0.112724");
  script_version("2020-04-06T07:22:46+0000");
  script_tag(name:"last_modification", value:"2020-04-06 12:43:58 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-06 06:54:11 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-10960");

  script_name("MediaWiki 1.31.x < 1.31.7, 1.33.x < 1.33.3 and 1.34.0 Web Interface Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to a vulnerability in the web interface.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability allows users to add various Cascading Style Sheets (CSS) classes
  (which can affect what content is shown or hidden in the user interface) to arbitrary DOM nodes via HTML content
  within a MediaWiki page.

  This occurs because jquery.makeCollapsible allows applying an event handler to any Cascading Style Sheets (CSS) selector.");
  script_tag(name:"impact", value:"Successful exploitation would allow the content of the page to affect the MediaWiki interface.");
  script_tag(name:"affected", value:"MediaWiki versions 1.31.0 through 1.31.6, 1.33.0 through 1.33.2 and 1.34.0.");
  script_tag(name:"solution", value:"Update to version 1.31.7, 1.33.3, or 1.34.1 respectively.");

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T246602");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/wikitech-l/2020-March/093243.html");

  exit(0);
}

CPE = "cpe:/a:mediawiki:mediawiki";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "1.31.0", test_version2: "1.31.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.31.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "1.33.0", test_version2: "1.33.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.33.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "1.34.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.34.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
