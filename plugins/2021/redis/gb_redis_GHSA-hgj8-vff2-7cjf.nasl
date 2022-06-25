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
  script_oid("1.3.6.1.4.1.25623.1.0.145471");
  script_version("2021-03-02T03:42:33+0000");
  script_tag(name:"last_modification", value:"2021-03-02 12:14:25 +0000 (Tue, 02 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-02 03:35:50 +0000 (Tue, 02 Mar 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2021-21309");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis Integer Overflow Vulnerability (GHSA-hgj8-vff2-7cjf)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to an integer overflow vulnerability.");

  script_tag(name:"insight", value:"An integer overflow bug in 32-bit Redis could be exploited to corrupt the
  heap and potentially result with remote code execution.

  Redis 4.0 or newer uses a configurable limit for the maximum supported bulk input size. By default, it is
  512MB which is a safe value for all platforms.

  If the limit is significantly increased, receiving a large request from a client may trigger several integer
  overflow scenarios, which would result with buffer overflow and heap corruption. This could in certain
  conditions be exploited for remote code execution.

  By default, authenticated Redis users have access to all configuration parameters and can therefore use the
  'CONFIG SET proto-max-bulk-len' to change the safe default, making the system vulnerable.

  This problem only affects 32-bit Redis (on a 32-bit system, or as a 32-bit executable running on a 64-bit
  system).");

  script_tag(name:"affected", value:"Redis version 4.0 and later.");

  script_tag(name:"solution", value:"Update to version 5.0.11, 6.0.11, 6.2 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-hgj8-vff2-7cjf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.0", test_version2: "5.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0", test_version2: "6.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.11");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
