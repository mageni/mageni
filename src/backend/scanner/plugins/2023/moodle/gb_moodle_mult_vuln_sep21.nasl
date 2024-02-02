# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118530");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-08-16 08:15:56 +0000 (Wed, 16 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-03 17:29:00 +0000 (Mon, 03 Oct 2022)");

  script_cve_id("CVE-2021-40691", "CVE-2021-40692", "CVE-2021-40693", "CVE-2021-40694",
                "CVE-2021-40695");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle Session Hijack Vulnerability (MSA-21-0032)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to a Session Hijack risk
  vulnerability when Shibboleth authentication is enabled.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-40691 / MSA-21-0032: A session hijack risk was identified in the Shibboleth
  authentication plugin.

  Note: Shibboleth authentication is disabled by default in Moodle.

  - CVE-2021-40692 / MSA-21-0033: Insufficient capability checks made it possible for teachers to
  download users outside of their courses.

  - CVE-2021-40693 / MSA-21-0034: An authentication bypass risk was identified in the external
  database authentication functionality, due to a type juggling vulnerability.

  - CVE-2021-40694 / MSA-21-0035: Insufficient escaping of the LaTeX preamble made it possible for
  site administrators to read files available to the HTTP server system account.

  - CVE-2021-40695 / MSA-21-0036: It was possible for a student to view their quiz grade before it
  had been released, using a quiz web service.");

  script_tag(name:"affected", value:"Moodle prior to version 3.9.10, 3.10 prior to 3.10.7 and 3.11
  prior to 3.11.3");

  script_tag(name:"solution", value:"Update to version 3.9.10, 3.10.7, 3.11.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=427103");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=427104");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=427105");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=427106");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=427107");


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

if (version_is_less(version: version, test_version: "3.9.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ( version_in_range( version: version, test_version: "3.10.0", test_version2: "3.10.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.10.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range( version: version, test_version: "3.11.0", test_version2: "3.11.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.11.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit(99);
