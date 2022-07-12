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
  script_oid("1.3.6.1.4.1.25623.1.0.113812");
  script_version("2021-04-09T10:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-09 14:31:10 +0000 (Fri, 09 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-09 10:46:46 +0000 (Fri, 09 Apr 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-14147");

  script_name("Redis < 6.0.3 Integer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to an integer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists in the getnum function in lua_struct.c.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  bypass sandbox restrictions or crash the application.");

  script_tag(name:"affected", value:"Redis through version 6.0.2.");

  script_tag(name:"solution", value:"Update to version 6.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/pull/6875");

  exit(0);
}

CPE = "cpe:/a:redis:redis";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "6.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );