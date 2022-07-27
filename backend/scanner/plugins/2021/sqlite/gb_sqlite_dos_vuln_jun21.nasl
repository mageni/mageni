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
  script_oid("1.3.6.1.4.1.25623.1.0.113819");
  script_version("2021-06-17T12:08:19+0000");
  script_tag(name:"last_modification", value:"2021-06-18 10:19:50 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 09:43:10 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-16168");

  script_name("SQLite 3.8.5 - 3.29.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"whereLoopAddBtreeIndex in sqlite3.c can crash a browser or
  another application because of missing validation of a sqlite_stat1 sz field, which can lead
  to a divide-by-zero error.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  crash the application and possibly other connected applications as well.");

  script_tag(name:"affected", value:"SQLite version 3.8.5 through 3.29.0.");

  script_tag(name:"solution", value:"No known solution is available as of 17th June, 2021.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg116312.html");
  script_xref(name:"URL", value:"https://www.sqlite.org/src/info/e4598ecbdd18bd82945f6029013296690e719a62");
  script_xref(name:"URL", value:"https://www.sqlite.org/src/info/b83367a95c48bf60");

  exit(0);
}

CPE = "cpe:/a:sqlite:sqlite";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "3.8.5", test_version2: "3.29.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
