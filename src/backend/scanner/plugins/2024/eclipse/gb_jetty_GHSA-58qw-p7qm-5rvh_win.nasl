# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151574");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-18 05:07:39 +0000 (Thu, 18 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:M/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty XXE Vulnerability (GHSA-58qw-p7qm-5rvh) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a XML external entity (XXE)
  vulnerability in the XMLParser.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"XmlParser is being used when parsing Jetty's xml configuration
  files. An attacker might exploit this vulnerability in order to achieve SSRF or cause a denial of
  service.

  One possible scenario is importing a (remote) malicious WAR into a Jetty's server, while the WAR
  includes a malicious web.xml.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.4.51 and prior, 10.0.0 through
  10.0.15 and 11.0.0 through 11.0.15.");

  script_tag(name:"solution", value:"Update to version 9.4.52, 10.0.16, 11.0.16 or later.");

  script_xref(name:"URL", value:"https://github.com/jetty/jetty.project/security/advisories/GHSA-58qw-p7qm-5rvh");

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

if (version_is_less(version: version, test_version: "9.4.52")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.52", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
