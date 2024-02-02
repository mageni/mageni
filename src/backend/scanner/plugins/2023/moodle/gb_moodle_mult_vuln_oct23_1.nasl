# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124448");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-10-23 08:29:42 +0000 (Mon, 23 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-17 16:36:00 +0000 (Fri, 17 Nov 2023)");

  script_cve_id("CVE-2023-5539", "CVE-2023-5540", "CVE-2023-5541", "CVE-2023-5544",
                "CVE-2023-5545", "CVE-2023-5547", "CVE-2023-5548", "CVE-2023-5549",
                "CVE-2023-5550", "CVE-2023-5551");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.9.24, 3.11.x < 3.11.17, 4.0.x < 4.0.11, 4.1.x < 4.1.6, 4.2.x < 4.2.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-5539 / MSA-23-0031: A remote code execution risk was identified in the Lesson activity.
  By default this was only available to teachers and managers.

  - CVE-2023-5540 / MSA-23-0032: A remote code execution risk was identified in the IMSCP activity.
  By default this was only available to teachers and managers.

  - CVE-2023-5541 / MSA-23-0033: The CSV grade import method contained an XSS risk for users
  importing the spreadsheet, if it contained unsafe content.

  - CVE-2023-5544 / MSA-23-0036: Wiki comments required additional sanitizing and access restrictions
  to prevent a stored XSS risk and potential IDOR risk.

  - CVE-2023-5545 / MSA-23-0037: H5P metadata automatically populated the author with the user's
  username, which could be sensitive information.

  - CVE-2023-5547 / MSA-23-0039: The course upload preview contained an XSS risk for users uploading
  unsafe data.

  - CVE-2023-5548 / MSA-23-0040: Stronger revision number limitations were required on file serving
  endpoints to improve cache poisoning protection.

  - CVE-2023-5549 / MSA-23-0041: Insufficient escaping of users' names in account confirmation
  email.

  - CVE-2023-5550 / MSA-23-0042: In a shared hosting environment that has been misconfigured to allow
  access to other users' content, a Moodle user who also has direct access to the web server
  outside of the Moodle webroot could utilise a local file include to achieve remote code execution.

  - CVE-2023-5551 / MSA-23-0043: Separate Groups mode restrictions were not honoured in the forum
  summary report, which would display users from other groups.");

  script_tag(name:"affected", value:"Moodle versions prior to 3.9.24, 3.11.x prior to 3.11.17,
  4.0.x prior to 4.0.11, 4.1.x prior to 4.1.6 and 4.2.x prior to 4.2.3.");

  script_tag(name:"solution", value:"Update to version 3.9.24, 3.11.17, 4.0.11, 4.1.6, 4.2.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451580");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451581");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451582");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451585");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451586");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451588");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451589");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451590");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451591");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451592");

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

if (version_is_less(version: version, test_version: "3.9.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.11", test_version_up: "3.11.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1", test_version_up: "4.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
