# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118371");
  script_version("2022-09-27T10:12:08+0000");
  script_tag(name:"last_modification", value:"2022-09-27 10:12:08 +0000 (Tue, 27 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-26 12:30:57 +0000 (Mon, 26 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-35951");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis 7.0.x < 7.0.5 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Executing a XAUTOCLAIM command on a stream key in a specific
  state, with a specially crafted COUNT argument, may cause an integer overflow, a subsequent heap
  overflow, and potentially lead to remote code execution.");

  script_tag(name:"affected", value:"Redis version 7.0.x prior to version 7.0.5.");

  script_tag(name:"solution", value:"Update to version 7.0.5 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.0.5");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-5gc4-76rx-22c9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range_exclusive( version:version, test_version_lo:"7.0.0", test_version_up:"7.0.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.0.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
