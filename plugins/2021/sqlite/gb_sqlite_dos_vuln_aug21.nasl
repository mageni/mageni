# Copyright (C) 2021 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118172");
  script_version("2021-08-25T13:35:28+0000");
  script_tag(name:"last_modification", value:"2021-08-25 13:35:28 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-25 12:18:34 +0200 (Wed, 25 Aug 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-36690");

  script_name("SQLite 3.36.3 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Segmentation fault vulnerability via the 'idxGetTableInfo'
  function, in which a crafted SQL query can cause a denial of service.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  crash the application and possibly other connected applications as well.");

  script_tag(name:"affected", value:"SQLite version 3.36.3.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references
  for more information.");

  script_xref(name:"URL", value:"https://www.sqlite.org/forum/forumpost/718c0a8d17");
  script_xref(name:"URL", value:"https://sqlite.org/src/info/b1e0c22ec981cf5f");

  exit(0);
}

CPE = "cpe:/a:sqlite:sqlite";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_equal( version:version, test_version:"3.36.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"Apply the patch", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
