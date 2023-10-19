# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104997");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-18 14:52:03 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:P/I:P/A:N");

  script_cve_id("CVE-2023-45145");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis Unix Socket Permission Access Bypass Vulnerability (GHSA-ghmp-889m-7cvx)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a vulnerability that allows to bypass desired
  Unix socket permissions on startup.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On startup, Redis begins listening on a Unix socket before
  adjusting its permissions to the user-provided configuration. If a permissive umask(2) is used,
  this creates a race condition that enables, during a short period of time, another process to
  establish an otherwise unauthorized connection.");

  # nb: There was no version 6.3.x, 7.1.x or similar.
  script_tag(name:"affected", value:"Redis versions starting from 2.6.0-RC1 and prior to 6.2.14,
  7.0.x prior to 7.0.14 and 7.2.x prior to 7.2.2.");

  script_tag(name:"solution", value:"Update to version 6.2.14, 7.0.14, 7.2.2 or later.

  It is also possible to work around the problem by disabling Unix sockets, starting Redis with a
  restrictive umask, or storing the Unix socket file in a protected directory.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-ghmp-889m-7cvx");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

# nb: Unlikely that our detection is able to catch the RC1 suffix in 2.6.0-RC1 but no one should
# run that version in production these days.
if (version_in_range_exclusive(version: version, test_version_lo: "2.6.0", test_version_up: "6.2.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.14");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.14");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.2", test_version_up: "7.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
