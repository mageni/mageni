# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104647");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-21 10:55:38 +0000 (Tue, 21 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2022-36021", "CVE-2023-25155");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis < 6.0.18, 6.2.x < 6.2.11, 7.0.x < 7.0.9 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-36021: String matching commands (like SCAN or KEYS) with a specially crafted pattern to
  trigger a denial-of-service attack on Redis, causing it to hang and consume 100% CPU time.

  - CVE-2023-25155: Specially crafted SRANDMEMBER, ZRANDMEMBER, and HRANDFIELD commands can trigger
  an integer overflow, resulting in a runtime assertion and termination of the Redis server
  process.");

  script_tag(name:"affected", value:"Redis versions prior to 6.0.18, 6.2.x prior to 6.2.11 and 7.0.x
  prior to 7.0.9.");

  script_tag(name:"solution", value:"Update to version 6.0.18, 6.2.11, 7.0.9 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-x2r7-j9vw-3w83");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-jr7j-rfj5-8xqv");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.0.9");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/6.2.11");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/6.0.18");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.0.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.18/6.2.11/7.0.9");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2.0", test_version_up: "6.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.11/7.0.9");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.9");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
