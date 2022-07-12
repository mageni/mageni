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

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145887");
  script_version("2021-05-05T03:10:24+0000");
  script_tag(name:"last_modification", value:"2021-05-05 10:22:53 +0000 (Wed, 05 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-05 03:01:11 +0000 (Wed, 05 May 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2021-29478");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis 6.2.x < 6.2.3 Integer Overflow Vulnerability (GHSA-qh52-crrg-44g3)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to an integer overflow vulnerability.");

  script_tag(name:"insight", value:"An integer overflow bug in Redis 6.2 could be exploited to
  corrupt the heap and potentially result with remote code execution.

  The vulnerability involves changing the default set-max-intset-entries configuration value,
  creating a large set key that consists of integer values and using the COPY command to duplicate
  it.

  The integer overflow bug exists in all versions of Redis starting with 2.6, where it could result
  with a corrupted RDB or DUMP payload, but not exploited through COPY (which did not exist before 6.2).");

  script_tag(name:"affected", value:"Redis version 6.2.x through 6.2.2.");

  script_tag(name:"solution", value:"Update to version 6.2.3 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-qh52-crrg-44g3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "6.2", test_version2: "6.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
