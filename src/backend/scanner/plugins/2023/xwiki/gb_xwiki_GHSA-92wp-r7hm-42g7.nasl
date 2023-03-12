# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170334");
  script_version("2023-03-09T10:09:20+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:20 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-06 08:42:52 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2023-26470");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 7.1-milestone-1 < 14.0-rc-1 Uncontrolled Resource Consumption Vulnerability (GHSA-92wp-r7hm-42g7)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to an uncontrolled resource consumption
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It's possible to make the farm unusable by adding an object to a
  page with a huge number (e.g. 67108863). This will most of the time fill the memory allocated to
  XWiki and make it unusable every time this document is manipulated.");

  script_tag(name:"affected", value:"XWiki version 7.1-milestone-1 prior to 14.0-rc-1.");

  script_tag(name:"solution", value:"Update to version 14.0-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-92wp-r7hm-42g7");
  script_xref(name:"URL", value:"https://jira.xwiki.org/browse/XWIKI-19223");
  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/commit/db3d1c62fc5fb59fefcda3b86065d2d362f55164");
  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/commit/fdfce062642b0ac062da5cda033d25482f4600fa");
  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/commit/04e5a89d2879b160cdfaea846024d3d9c1a525e6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"7.1-milestone-1", test_version_up:"14.0-rc-1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.0-rc-1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
