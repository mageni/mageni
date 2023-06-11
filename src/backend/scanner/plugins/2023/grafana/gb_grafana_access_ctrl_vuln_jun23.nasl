# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149749");
  script_version("2023-06-08T05:05:11+0000");
  script_tag(name:"last_modification", value:"2023-06-08 05:05:11 +0000 (Thu, 08 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-07 03:21:18 +0000 (Wed, 07 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2023-2183");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana < 8.5.26, 9.x < 9.2.19, 9.3.x < 9.3.15, 9.4.x < 9.4.12, 9.5.0 < 9.5.3 Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to an access control vulnerability in the
  alert manager.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The option to send a test alert is not available from the user
  panel UI for users having the Viewer role. It is still possible for a user with the Viewer role
  to send a test alert using the API as the API does not check access to this function. This might
  enable malicious users to abuse the functionality by sending multiple alert messages to e-mail
  and Slack, spamming users, prepare phishing attack or block SMTP server.");

  script_tag(name:"affected", value:"Grafana prior to version 8.5.26, version 9.x through 9.2.18,
  9.3.x through 9.3.14, 9.4.x through 9.4.11 and version 9.5.x through 9.5.2.");

  script_tag(name:"solution", value:"Update to version 8.5.26, 9.2.19, 9.3.15, 9.4.12, 9.5.3 or
  later.");

  script_xref(name:"URL", value:"https://grafana.com/security/security-advisories/cve-2023-2183/");

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

if (version_is_less(version: version, test_version: "8.5.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0", test_version_up: "9.2.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3.0", test_version_up: "9.3.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.4.0", test_version_up: "9.4.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.5.0", test_version_up: "9.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
