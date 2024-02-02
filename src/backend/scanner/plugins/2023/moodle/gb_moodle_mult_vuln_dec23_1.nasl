# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126620");
  script_version("2023-12-29T16:09:56+0000");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-28 08:01:42 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-6661", "CVE-2023-6662", "CVE-2023-6663", "CVE-2023-6664",
                "CVE-2023-6667", "CVE-2023-6668", "CVE-2023-6669");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.9.25, 3.11.x < 3.11.18, 4.0.x < 4.0.12, 4.1.x < 4.1.7, 4.2.x < 4.2.4, 4.3.x < 4.3.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-6661 / MSA-23-0044: A remote code execution risk was identified in logstore. By
  default this was only available to managers.

  - CVE-2023-6662 / MSA-23-0045: Insufficient recursion limitations resulted in a denial of
  service risk in the URL downloader.

  - CVE-2023-6663 / MSA-23-0046: A remote code execution risk was identified in course blocks. By
  default this was only available to teachers and managers.

  - CVE-2023-6664 / MSA-23-0047: Separate Groups mode restrictions were not honoured in the Logs
  and Live logs course reports, which would display users from other groups.

  - CVE-2023-6667 / MSA-23-0050: Separate Groups mode restrictions were not honoured in survey
  response reports, which would display users from other groups.

  - CVE-2023-6668 / MSA-23-0051: Insufficient capability checks meant it was possible for all users
  to view the recipients of badges.

  - CVE-2023-6669 / MSA-23-0052: The mtrace output when running a task in the admin UI required
  additional sanitizing to prevent an XSS risk.");

  script_tag(name:"affected", value:"Moodle versions prior to 3.9.25, 3.11.x prior to 3.11.18,
  4.0.x prior to 4.0.12, 4.1.x prior to 4.1.7, 4.2.x prior to 4.2.4 and 4.3.x prior to 4.3.1.");

  script_tag(name:"solution", value:"Update to version 3.9.25, 3.11.18, 4.0.12, 4.1.7, 4.2.4, 4.3.1
  or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=453758");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=453759");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=453760");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=453761");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=453764");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=453765");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=453766");

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

if (version_is_less(version: version, test_version: "3.9.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.11", test_version_up: "3.11.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1", test_version_up: "4.1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

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
