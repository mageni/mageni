# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126550");
  script_version("2024-01-24T05:06:24+0000");
  script_tag(name:"last_modification", value:"2024-01-24 05:06:24 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-12-01 13:07:25 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 05:34:00 +0000 (Thu, 30 Nov 2023)");

  script_cve_id("CVE-2023-4220", "CVE-2023-4221", "CVE-2023-4222", "CVE-2023-4223",
                "CVE-2023-4224", "CVE-2023-4225", "CVE-2023-4226");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Chamilo LMS 1.11.x < 1.11.24 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-4220: Unauthenticated users could exploit a vulnerability in the upload of files,
  leading to a cross-site scripting (XSS) and a remote code execution (RCE).

  - CVE-2023-4221: Authenticated users (teachers) could exploit a vulnerability in the upload of
  learning paths, leading to a remote code execution (RCE). It's possible when Chamilo RAPID/Oogie
  is enabled and targeting localhost.

  - CVE-2023-4222: Authenticated users (teachers) could exploit a vulnerability in the upload of
  learning paths, leading to a remote code execution (RCE). It's possible when Chamilo RAPID/Oogie
  is enabled and targeting localhost.

  - CVE-2023-4223: Authenticated users (students) could exploit a vulnerability in the upload of
  files, leading to a remote code execution (RCE).

  - CVE-2023-4224: Authenticated users (students) could exploit a vulnerability in the upload of
  files, leading to a remote code execution (RCE).

  - CVE-2023-4225: Authenticated users (students) could exploit a vulnerability in the upload of
  files, leading to a remote code execution (RCE).

  - CVE-2023-4226: Authenticated users (students) could exploit a vulnerability in the upload of
  files, leading to a remote code execution (RCE).");

  script_tag(name:"affected", value:"Chamilo LMS version 1.11.x prior to 1.11.24.");

  script_tag(name:"solution", value:"Update to version 1.11.24 or later");

  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/security_issues#Issue-130-2023-09-04-Critical-impact-High-risk-Unauthenticated-users-may-gain-XSS-and-unauthenticated-RCE-CVE-2023-4220");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/security_issues#Issue-128-2023-09-04-Critical-impact-Moderate-risk-Authenticated-users-may-gain-unauthenticated-RCE-CVE-2023-4221CVE-2023-4222");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/security_issues#Issue-129-2023-09-04-Critical-impact-Moderate-risk-Authenticated-users-may-gain-unauthenticated-RCE-CVE-2023-4223CVE-2023-4224CVE-2023-4225CVE-2023-4226");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.11.0", test_version_up: "1.11.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
