# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170684");
  script_version("2023-11-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-11-22 05:05:24 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-13 12:32:02 +0000 (Mon, 13 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 18:08:00 +0000 (Tue, 14 Nov 2023)");

  script_cve_id("CVE-2023-45868");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 7.26, 8.x < 8.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"ILIAS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-45868/ 38226: [Exercise] Exercise: Local File Inclusion/Rename

  - 28626: [General] Prevent some alternative php-suffixes from upload and unzipping

  - 37930: [Media Pools and Media Objects] Remote code execution via zip upload

  - 38188: [Test & Assessment] Editing taxonomies is possible on a question pool that is online, but
  to which the user has only read and/or view access

  - 37995: [RBAC] RBAC: Fix permission check to add users to the admin role in role settings when
  admin role is protected

  - 32836: [General] Reauthentication required to Change E-Mail");

  script_tag(name:"affected", value:"ILIAS prior to version 7.26 and 8.x prior to 8.6.");

  script_tag(name:"solution", value:"Update to version 7.26, 8.6 or later.");

  script_xref(name:"URL", value:"https://rehmeinfosec.de/labor/cve-2023-45867");
  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_154839_35.html");
  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_154840_35.html");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
