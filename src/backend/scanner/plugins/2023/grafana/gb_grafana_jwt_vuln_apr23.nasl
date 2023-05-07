# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149589");
  script_version("2023-05-04T09:51:03+0000");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"creation_date", value:"2023-04-27 04:27:12 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:M/C:C/I:N/A:N");

  script_cve_id("CVE-2023-1387");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 9.1.0 < 9.2.17, 9.3.x < 9.3.13, 9.4.x < 9.4.9 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Starting with the 9.1 branch, Grafana introduced the ability to
  search for a JWT in the URL query parameter auth_token and use it as the authentication token. By
  enabling the 'url_login' configuration option (disabled by default), a JWT might be sent to data
  sources. If an attacker has access to the data source, the leaked token could be used to
  authenticate to Grafana.");

  script_tag(name:"affected", value:"Grafana versions starting from 9.1.0 and prior to 9.2.17, 9.3.x
  prior to 9.3.13 and 9.4.x prior to 9.4.9.");

  script_tag(name:"solution", value:"Update to version 9.2.17, 9.3.13, 9.4.9 or later.");

  script_xref(name:"URL", value:"https://grafana.com/security/security-advisories/cve-2023-1387/");
  script_xref(name:"URL", value:"https://grafana.com/blog/2023/04/26/grafana-security-release-new-versions-of-grafana-with-security-fixes-for-cve-2023-28119-and-cve-2023-1387/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "9.1.0", test_version_up: "9.2.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3.0", test_version_up: "9.3.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.4.0", test_version_up: "9.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
