# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126164");
  script_version("2023-11-07T05:06:14+0000");
  script_tag(name:"last_modification", value:"2023-11-07 05:06:14 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"creation_date", value:"2022-10-10 10:40:17 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-04 16:51:00 +0000 (Tue, 04 Oct 2022)");

  script_cve_id("CVE-2022-40313", "CVE-2022-40314", "CVE-2022-40315", "CVE-2022-40316");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.9.17, 3.11 < 3.11.10, 4.0 < 4.0.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-40313 / MSA-22-0023: Recursive rendering of Mustache template helpers containing user
  input could, in some cases, result in an XSS risk or a page failing to load.

  - CVE-2023-40314 / MSA-22-0024: A remote code execution risk when restoring backup files
  originating from Moodle 1.9 was identified.

  - CVE-2023-40315 / MSA-22-0025: A limited SQL injection risk was identified in the 'browse list
  of users' site administration page.

  - CVE-2023-40316 / MSA-22-0026: The H5P activity attempts report did not filter by groups, which
  in separate groups mode could reveal information to non-editing teachers about attempts/users in
  groups they should not have access to.");

  script_tag(name:"affected", value:"Moodle versions prior to 3.9.17, 3.11.x prior to  3.11.10 and
  4.0.x prior to 4.0.4.");

  script_tag(name:"solution", value:"Update to version 3.9.17, 3.11.10, 4.0.4 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=438392");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=438393");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=438394");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=438395");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "3.9.0", test_version_up: "3.9.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.11.0", test_version_up: "3.11.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
