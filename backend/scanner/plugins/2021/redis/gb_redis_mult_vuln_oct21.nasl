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
  script_oid("1.3.6.1.4.1.25623.1.0.146848");
  script_version("2021-10-06T13:05:51+0000");
  script_tag(name:"last_modification", value:"2021-10-07 11:23:18 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-06 12:53:39 +0000 (Wed, 06 Oct 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2021-32628", "CVE-2021-32675", "CVE-2021-32687", "CVE-2021-32762", "CVE-2021-41099");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis < 5.0.14, 6.0.x < 6.0.16, 6.1.x < 6.2.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-32628: Integer overflow in the ziplist data structure

  - CVE-2021-32675: Denial of Service (DoS)

  - CVE-2021-32687: Integer overflow in intsets

  - CVE-2021-32762: Integer overflow in redis-cli and redis-sentinel

  - CVE-2021-41099: Integer overflow in the underlying string library");

  script_tag(name:"affected", value:"Redis prior to version 5.0.14, version 6.0.x through 6.0.15
  and 6.1.x through 6.2.5.");

  script_tag(name:"solution", value:"Update to version 5.0.14, 6.0.16, 6.2.6 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-vw22-qm3h-49pr");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-f6pw-v9gw-v64p");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-m3mf-8x9w-r27q");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-833w-8v3m-8wwr");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-j3cr-9h5g-6cph");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.14");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0", test_version2: "6.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.1", test_version2: "6.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
