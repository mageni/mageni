# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126364");
  script_version("2023-05-12T10:50:26+0000");
  script_tag(name:"last_modification", value:"2023-05-12 10:50:26 +0000 (Fri, 12 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-10 08:47:25 +0000 (Wed, 10 May 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2023-31799", "CVE-2023-31800", "CVE-2023-31801", "CVE-2023-31802",
                "CVE-2023-31803", "CVE-2023-31804", "CVE-2023-31805", "CVE-2023-31806",
                "CVE-2023-31807");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Chamilo LMS 1.11.x <= 1.11.18 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-31799: An administrator could edit system announcements and insert XSS attacks.

  - CVE-2023-31800: Teachers and students through student group could add XSS into a forum title.

  - CVE-2023-31801: XSS through links pointing at the skills wheel.

  - CVE-2023-31802: A user could add XSS to his/her own profile on the social network.

  - CVE-2023-31803: An administrator could edit resources sequencing and insert XSS attacks.

  - CVE-2023-31804: XSS attacks in course category edition, specifically targeting Chamilo
  administrators.

  - CVE-2023-31805: An administrator could edit links on the homepage and insert XSS attacks.

  - CVE-2023-31806: A User could add XSS into its personal notes.

  - CVE-2023-31807: An attacker is able to enumerate the internal network and execute arbitrary
  system commands via a crafted Phar file.");

  script_tag(name:"affected", value:"Chamilo LMS version 1.11.x through 1.11.18.");

  script_tag(name:"solution", value:"No known solution is available as of 11th May, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-99-2023-04-11-Low-impact-Low-risk-XSS-in-system-announcements");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-102-2023-04-11-Low-impact-Moderate-risk-XSS-in-forum-titles");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-97-2023-04-11-Low-impact-High-risk-XSS-in-skills-wheel");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-104-2023-04-11-Moderate-impact-High-risk-XSS-in-personal-profile");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-100-2023-04-11-Low-impact-Low-risk-XSS-in-resources-sequencing");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-96-2023-04-06-Low-impact-Moderate-risk-XSS-in-course-categories");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-98-2023-04-11-Low-impact-Low-risk-XSS-in-homepage-edition");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-103-2023-04-11-Low-impact-Moderate-risk-XSS-in-My-progress-tab");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-101-2023-04-11-Low-impact-Low-risk-XSS-in-personal-notes-and-teacher-notes");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.11.0", test_version_up: "1.11.18")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
    security_message(port: port, data: report);
    exit(0);
}

exit(0);
