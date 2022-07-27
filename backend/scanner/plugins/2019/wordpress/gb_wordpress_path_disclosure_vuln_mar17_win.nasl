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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113415");
  script_version("2019-06-24T10:12:27+0000");
  script_tag(name:"last_modification", value:"2019-06-24 10:12:27 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-24 11:55:30 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-6514");
  script_bugtraq_id(108459);

  script_name("WordPress <= 4.7.2 Path Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to a path disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists because WordPress mishandles the listings of post authors,
  which allows remote attackers to obtain sensitive information via a
  /wp-json/oembed/1.0/embed?url= request, related to the 'author_name:' substring.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access sensitive information.");
  script_tag(name:"affected", value:"WordPress through version 4.7.2.");
  script_tag(name:"solution", value:"Update to version 4.7.3 or above.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20180612235401/https://github.com/CFSECURITE/wordpress");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.7.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.7.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
