# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124399");
  script_version("2023-08-23T05:05:12+0000");
  script_tag(name:"last_modification", value:"2023-08-23 05:05:12 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-03 07:47:25 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-34960", "CVE-2023-37061", "CVE-2023-37062", "CVE-2023-37063",
                "CVE-2023-37064", "CVE-2023-37065", "CVE-2023-37066", "CVE-2023-37067",
                "CVE-2023-39061");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Chamilo LMS 1.11.x < 1.11.20 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-34960: Attackers are able to execute arbitrary commands via a SOAP API call with a crafted PowerPoint name.

  - CVE-2023-37061: Users with an admin privilege account are able to insert XSS in the languages
  management section.

  - CVE-2023-37062: Users with admin privilege account are able to insert XSS in the course
  categories' definition.

  - CVE-2023-37063: Users with admin privilege account are able to insert XSS in the careers &
  promotions management section.

  - CVE-2023-37064: Users with admin privilege account are able to insert XSS in the extra fields
  management section.

  - CVE-2023-37065: Users with admin privilege account are able to insert XSS in the session
  category management section.

  - CVE-2023-37066: Users with admin privilege account are able to insert XSS in the skills wheel.

  - CVE-2023-37067: Users with admin privilege account are able to insert XSS in the
  classes/usergroups management section.

  - CVE-2023-39061: Cross site request forgery (CSRF) through admin account.");

  script_tag(name:"affected", value:"Chamilo LMS version 1.11.x prior to 1.11.20.");

  script_tag(name:"solution", value:"Update to version 1.11.20 or later");

  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-112-2023-04-20-Critical-impact-High-risk-Remote-Code-Execution");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-116-2023-06-06-Low-impact-Low-risk-XSS-through-admin-account-languages-management");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-115-2023-06-06-Low-impact-Low-risk-XSS-through-admin-account-course-category");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-117-2023-06-06-Low-impact-Low-risk-XSS-through-admin-account-careers-amp-promotions-management");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-119-2023-06-06-Low-impact-Low-risk-XSS-through-admin-account-extra-fields-management");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-118-2023-06-06-Low-impact-Low-risk-XSS-through-admin-account-session-category-management");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-114-2023-06-06-Low-impact-Low-risk-XSS-through-admin-account-skills");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-120-2023-06-07-Low-impact-Low-risk-XSS-through-admin-account-classesusergroups-management");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-123-2023-07-08-Moderate-impact-Moderate-risk-CSRF-through-admin-account-forum-posts");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.11.0", test_version_up: "1.11.20")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.11.20", install_path: location);
    security_message(port: port, data: report);
    exit(0);
}

exit(99);
