# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151433");
  script_version("2024-01-05T16:09:35+0000");
  script_tag(name:"last_modification", value:"2024-01-05 16:09:35 +0000 (Fri, 05 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-12-20 07:51:45 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-03 14:29:00 +0000 (Wed, 03 Jan 2024)");

  script_cve_id("CVE-2023-49791", "CVE-2023-49792");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server Multiple Vulnerabilities (GHSA-3f8p-6qww-2prr, GHSA-5j2p-q736-hw98)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-49791: Workflows do not require password confirmation on API level

  - CVE-2023-49792: Bruteforce protection can be bypassed with misconfigured proxy");

  script_tag(name:"affected", value:"Nextcloud Server version 23.x prior to 23.0.12.13, 24.x prior
  to 24.0.12.9, 25.x prior to 25.0.13.4, 26.x prior to 26.0.9 and 27.x prior to 27.1.4.");

  script_tag(name:"solution", value:"Update to version 23.0.12.13, 24.0.12.9, 25.0.13.4, 26.0.9,
  27.1.4 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-3f8p-6qww-2prr");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-5j2p-q736-hw98");

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

if (version_in_range_exclusive(version: version, test_version_lo: "23.0", test_version_up: "23.0.12.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "23.0.12.13 (Nextcloud Enterprise only)", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "24.0", test_version_up: "24.0.12.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.0.12.9 (Nextcloud Enterprise only)", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "25.0", test_version_up: "25.0.13.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "25.0.13.4 (Nextcloud Enterprise only)", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "26.0", test_version_up: "26.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "26.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "27.0", test_version_up: "27.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "27.1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
