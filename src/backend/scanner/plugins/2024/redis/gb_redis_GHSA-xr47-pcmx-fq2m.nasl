# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114259");
  script_version("2024-01-24T14:38:46+0000");
  script_tag(name:"last_modification", value:"2024-01-24 14:38:46 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-10 13:40:01 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-22 18:58:00 +0000 (Mon, 22 Jan 2024)");

  script_cve_id("CVE-2023-41056");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis RCE Vulnerability (GHSA-xr47-pcmx-fq2m)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In some cases, Redis may incorrectly handle resizing of memory
  buffers which can result in incorrect accounting of buffer sizes and lead to heap overflow and
  potential remote code execution.");

  # nb: There was no version 7.1.x.
  script_tag(name:"affected", value:"Redis versions starting from 7.0.9 and prior to 7.0.15 and
  7.2.x prior to 7.2.4.");

  script_tag(name:"solution", value:"Update to version 7.0.15, 7.2.4 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-xr47-pcmx-fq2m");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.2.4");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.0.15");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.9", test_version_up: "7.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.15");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.2", test_version_up: "7.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
