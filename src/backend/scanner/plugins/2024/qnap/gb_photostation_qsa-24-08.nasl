# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:qnap:photo_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151650");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-05 08:17:09 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-07 17:50:38 +0000 (Wed, 07 Feb 2024)");

  script_cve_id("CVE-2023-47561", "CVE-2023-47562");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP Photo Station Multiple Vulnerabilities (QSA-24-08)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_photo_station_detect.nasl");
  script_mandatory_keys("qnap/nas/PhotoStation/detected");

  script_tag(name:"summary", value:"QNAP Photo Station is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-47561: Cross-site scripting (XSS) could allow authenticated users to inject malicious
  code via a network.

  - CVE-2023-47562: OS command injection could allow authenticated users to execute commands via a
  network.");

  script_tag(name:"affected", value:"QNAP Photo Station version 6.4.x.");

  script_tag(name:"solution", value:"Update to version 6.4.2 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-08");

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

if (version_in_range_exclusive(version: version, test_version_lo: "6.4", test_version_up: "6.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
