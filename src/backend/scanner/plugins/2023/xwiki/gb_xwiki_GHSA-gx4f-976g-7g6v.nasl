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
  script_oid("1.3.6.1.4.1.25623.1.0.170351");
  script_version("2023-03-09T10:09:20+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:20 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-08 21:37:52 +0000 (Wed, 08 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_cve_id("CVE-2023-27480");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 1.1-milestone-3 < 13.10.11, 14.x < 14.4.7, 14.5.x < 14.10 XXE Vulnerability (GHSA-gx4f-976g-7g6v)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to an XML external entity injection (XXE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Any user with edit rights on a document can trigger a XAR import
  on a forged XAR file, leading to the ability to display the content of any file on the XWiki
  server host.");

  script_tag(name:"affected", value:"XWiki version 1.1-milestone-3 prior to 13.10.11, 14.x prior to
  14.4.7 and 14.5.x prior to 14.10.");

  script_tag(name:"solution", value:"Update to version 13.10.11, 14.4.7, 14.10 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-gx4f-976g-7g6v");
  script_xref(name:"url", value:"https://jira.xwiki.org/browse/XWIKI-20320");
  script_xref(name:"url", value:"https://github.com/xwiki/xwiki-platform/commit/e3527b98fdd8dc8179c24dc55e662b2c55199434");

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

if( version_in_range_exclusive( version:version, test_version_lo:"1.1-milestone-3", test_version_up:"13.10.11" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.10.11", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"14.0", test_version_up:"14.4.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.4.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range_exclusive( version:version, test_version_lo:"14.5", test_version_up:"14.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
