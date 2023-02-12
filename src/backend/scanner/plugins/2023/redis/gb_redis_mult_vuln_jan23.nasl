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

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149156");
  script_version("2023-01-19T10:10:48+0000");
  script_tag(name:"last_modification", value:"2023-01-19 10:10:48 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-18 03:52:35 +0000 (Wed, 18 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2022-35977", "CVE-2023-22458");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis 6.2.x < 6.2.9, 7.0.x < 7.0.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-35977: Integer overflow in the Redis SETRANGE and SORT/SORT_RO commands can drive
  Redis to OOM panic

  - CVE-2023-22458: Integer overflow in the Redis HRANDFIELD and ZRANDMEMBER commands can lead to
  denial of service");

  script_tag(name:"affected", value:"Redis version 6.2.x through 6.2.8 and 7.0.x through 7.0.7.");

  script_tag(name:"solution", value:"Update to version 6.2.9, 7.0.8 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/6.2.9");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.0.8");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.2.0", test_version_up: "6.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.9");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.8");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
