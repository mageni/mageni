# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104715");
  script_version("2023-05-04T09:51:03+0000");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"creation_date", value:"2023-04-27 09:44:36 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-28119");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 7.3.0-beta1 < 8.5.24, 9.x < 9.2.17, 9.3.x < 9.3.13, 9.4.x < 9.4.9 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a denial of service (DoS) vulnerability in
  the crewjam/saml library used for SAML integration.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Grafana is using crewjam/saml library for SAML integration. On
  March 23, an advisory and relevant fix was published in the upstream library, which described a
  vulnerability allowing denial of service attack.");

  script_tag(name:"impact", value:"The use of flate.NewReader in crewjam/saml does not limit the
  size of the input. The user could pass more than 1 MB of data in the HTTP request to the
  processing functions, which will be decompressed server-side using the Deflate algorithm.
  Therefore, after repeating the same request multiple times, it is possible to achieve a reliable
  crash since the operating system kills the process.

  In Grafana Enterprise, SAML single logout is using the aforementioned functions. Therefore, it's
  impacted by the vulnerability.");

  script_tag(name:"affected", value:"Grafana versions starting from 7.3.0-beta1 and prior to 8.5.24,
  9.x prior to 9.2.17, 9.3.x prior to 9.3.13 and 9.4.x prior to 9.4.9.");

  script_tag(name:"solution", value:"- Update to version 8.5.24, 9.2.17, 9.3.13, 9.4.9 or later.

  - As an alternative mitigation, disabling single logout in SAML or not using the SAML
  authentication entirely would mitigate the vulnerability.");

  script_xref(name:"URL", value:"https://grafana.com/blog/2023/04/26/grafana-security-release-new-versions-of-grafana-with-security-fixes-for-cve-2023-28119-and-cve-2023-1387/");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-5mqj-xc49-246p");

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

if (version_in_range_exclusive(version: version, test_version_lo: "7.3.0", test_version_up: "8.5.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0", test_version_up: "9.2.17")) {
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
