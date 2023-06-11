# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149748");
  script_version("2023-06-08T05:05:11+0000");
  script_tag(name:"last_modification", value:"2023-06-08 05:05:11 +0000 (Thu, 08 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-07 03:14:09 +0000 (Wed, 07 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-2801");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana < 9.4.12, 9.5.0 < 9.5.3 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Using public dashboards users can query multiple distinct data
  sources using mixed queries. However such query has a possibility of crashing a Grafana instance.
  The only feature that uses mixed queries at the moment is public dashboards, but it's also
  possible to cause this by calling the query API directly. This might enable malicious users to
  crash Grafana instances through that endpoint.");

  script_tag(name:"affected", value:"Grafana prior to version 9.4.12 and version 9.5.x through
  9.5.2.");

  script_tag(name:"solution", value:"Update to version 9.4.12, 9.5.3 or later.");

  script_xref(name:"URL", value:"https://grafana.com/security/security-advisories/cve-2023-2801/");

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

if (version_is_less(version: version, test_version: "9.4.12")) {
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
