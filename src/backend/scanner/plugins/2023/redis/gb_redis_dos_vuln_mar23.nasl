# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104646");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-21 10:55:38 +0000 (Tue, 21 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2023-28425");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis 7.0.8 - 7.0.9 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Specially crafted MSETNX command can lead to assertion and
  denial-of-service.");

  script_tag(name:"affected", value:"Redis versions starting from 7.0.8 and prior to 7.0.10.");

  script_tag(name:"solution", value:"Update to version 7.0.10 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-mvmm-4vq6-vw8c");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.0.10");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.8", test_version_up: "7.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.10");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
