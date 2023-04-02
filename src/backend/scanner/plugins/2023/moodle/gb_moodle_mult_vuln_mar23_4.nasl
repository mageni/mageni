# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126025");
  script_version("2023-03-27T10:09:49+0000");
  script_tag(name:"last_modification", value:"2023-03-27 10:09:49 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-24 10:31:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");

  script_cve_id("CVE-2023-1402", "CVE-2023-28329", "CVE-2023-28330", "CVE-2023-28331",
                "CVE-2023-28332", "CVE-2023-28333", "CVE-2023-28336");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 3.9 < 3.9.20, 3.11 < 3.11.13, 4.0 < 4.0.7, 4.1 < 4.1.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-1402 / MSA-23-0012: The course participation report required additional checks to prevent
  roles being displayed which the user did not have access to view.

  - CVE-2023-28329 / MSA-23-0004: Insufficient validation of profile field availability condition
  resulted in an SQL injection risk (by default only available to teachers and managers).

  - CVE-2023-28330 / MSA-23-0005: Insufficient sanitizing in backup resulted in an arbitrary file
  read risk. The capability to access this feature is only available to teachers, managers and admins
  by default.

  - CVE-2023-28331 / MSA-23-0006: Content output by the database auto-linking filter required
  additional sanitizing to prevent an XSS risk.

  - CVE-2023-28332 / MSA-23-0007: If the algebra filter was enabled but not functional (eg the
  necessary binaries were missing from the server), it presented an XSS risk.

  - CVE-2023-28333 / MSA-23-0008: The Mustache pix helper contained a potential Mustache injection
  risk if combined with user input (note: This did not appear to be implemented/exploitable anywhere
  in the core Moodle LMS).

  - CVE-2023-28336 / MSA-23-0011: Insufficient filtering of grade report history made it possible for
  teachers to access the names of users they could not otherwise access.");

  script_tag(name:"affected", value:"Moodle versions 3.9 prior to 3.9.20, 3.11 prior to 3.11.12,
  4.0 prior to 4.0.7 and 4.1 prior to 4.1.2.");

  script_tag(name:"solution", value:"Update to version 3.9.20, 3.11.12, 4.0.7, 4.1.2 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=445061");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=445062");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=445063");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=445064");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=445065");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=445068");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=445069");


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

if (version_in_range_exclusive(version: version, test_version_lo: "3.9", test_version_up: "3.9.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.20");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.11", test_version_up: "3.11.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.12");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.7");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1", test_version_up: "4.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
