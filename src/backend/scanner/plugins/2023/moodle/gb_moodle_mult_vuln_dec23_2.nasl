# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126621");
  script_version("2023-12-29T16:09:56+0000");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-28 08:01:42 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-6665", "CVE-2023-6666", "CVE-2023-6670");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 4.2.x < 4.2.4, 4.3.x < 4.3.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-6665 / MSA-23-0048: ID numbers displayed in the grader report required additional
  sanitizing to prevent a stored XSS risk.

  - CVE-2023-6666 / MSA-23-0049: The grader report search required additional sanitizing to prevent
  a reflected XSS risk.

  - CVE-2023-6670 / MSA-23-0053: The 'classname' parameter on the admin ad-hoc tasks page required
  additional sanitizing to prevent a reflected XSS risk.");

  script_tag(name:"affected", value:"Moodle versions 4.2.x prior to 4.2.4 and 4.3.x prior to
  4.3.1.");

  script_tag(name:"solution", value:"Update to version 4.2.4, 4.3.1 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=453762");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=453763");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=453767");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3", test_version_up: "4.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);