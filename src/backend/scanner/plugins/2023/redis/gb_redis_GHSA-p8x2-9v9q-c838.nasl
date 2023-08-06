# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149921");
  script_version("2023-07-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-07-13 05:06:09 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 04:19:53 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-24834");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis < 6.0.20, 6.2.x < 6.2.13, 7.x < 7.0.12 Heap Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a heap overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A specially crafted Lua script executing in Redis can trigger a
  heap overflow in the cjson and cmsgpack libraries, and result in heap corruption and potentially
  remote code execution.");

  script_tag(name:"affected", value:"Redis prior to version 6.0.20, version 6.2.x through 6.2.12
  and 7.x through 7.0.11.");

  script_tag(name:"solution", value:"Update to version 6.0.20, 6.2.13, 7.0.12 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-p8x2-9v9q-c838");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.0.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.20");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2.0", test_version_up: "6.2.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.13");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.12");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
