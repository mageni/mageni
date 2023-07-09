# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124338");
  script_version("2023-06-20T05:05:27+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:27 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-19 08:08:40 +0000 (Mon, 19 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-35141");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins CSRF Vulnerability (CVE-2023-35141) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins is prone to a cross-site request forgery (CSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"POST requests are sent in order to load the list of context
  actions. If part of the URL includes insufficiently escaped user-provided values, a victim may
  be tricked into sending a POST request to an unexpected endpoint by opening a context menu.");

  script_tag(name:"affected", value:"Jenkins version through 2.387.3 (LTS) and version through
  2.399.");

  script_tag(name:"solution", value:"Update to version 2.401.1 (LTS), 2.400 or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2023-06-14/#SECURITY-3135");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (get_kb_item("jenkins/" + port + "/is_lts")) {
  if (version_is_less_equal(version: version, test_version: "2.387.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.401.1", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
} else {
  if (version_is_less_equal(version: version, test_version: "2.399")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.400", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}
exit(99);
