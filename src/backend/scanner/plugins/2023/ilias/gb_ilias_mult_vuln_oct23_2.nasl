# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170685");
  script_version("2023-11-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-11-22 05:05:24 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-13 12:32:02 +0000 (Mon, 13 Nov 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 17:40:00 +0000 (Tue, 14 Nov 2023)");

  script_cve_id("CVE-2023-45867", "CVE-2023-45869");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 7.26 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"ILIAS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-45867 / 38225: [SCORM Online Editor] SCORM Export: Local File Inclusion

  - CVE-2023-45869 / 38075: [PDF] PDF Generation: OS Command Injection Vulnerability");

  script_tag(name:"affected", value:"ILIAS prior to version 7.26.");

  script_tag(name:"solution", value:"Update to version 7.26 or later.");

  script_xref(name:"URL", value:"https://rehmeinfosec.de/labor/cve-2023-45867");
  script_xref(name:"URL", value:"https://rehmeinfosec.de/labor/cve-2023-45869");
  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_154839_35.html");

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

if (version_is_less(version: version, test_version: "7.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
