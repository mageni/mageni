# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151598");
  script_version("2024-01-31T14:37:46+0000");
  script_tag(name:"last_modification", value:"2024-01-31 14:37:46 +0000 (Wed, 31 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-24 04:20:52 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-30 23:05:12 +0000 (Tue, 30 Jan 2024)");

  script_cve_id("CVE-2024-23638");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid DoS Vulnerability (GHSA-j49p-553x-48rx, SQUID-2023:11)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to an expired pointer reference bug Squid is vulnerable to
  a denial of service attack against Cache Manager error responses.");

  script_tag(name:"affected", value:"Squid versions prior to 6.6.");

  script_tag(name:"solution", value:"Update to version 6.6 or later.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-j49p-553x-48rx");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "6.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
