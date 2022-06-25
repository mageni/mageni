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
  script_oid("1.3.6.1.4.1.25623.1.0.148021");
  script_version("2022-05-03T02:23:46+0000");
  script_tag(name:"last_modification", value:"2022-05-03 10:03:50 +0000 (Tue, 03 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-03 02:18:49 +0000 (Tue, 03 May 2022)");
  script_tag(name:"cvss_base", value:"3.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2022-24735", "CVE-2022-24736");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis < 6.2.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-24735: Lua scripts can be manipulated to overcome ACL rules

  - CVE-2022-24736: A malformed Lua script can crash Redis");

  script_tag(name:"affected", value:"Redis prior to version 6.2.7.");

  script_tag(name:"solution", value:"Update to version 6.2.7 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-647m-2wmq-qmvq");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-3qpw-7686-5984");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
