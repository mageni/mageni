# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149570");
  script_version("2023-04-21T04:45:14+0000");
  script_tag(name:"last_modification", value:"2023-04-21 04:45:14 +0000 (Fri, 21 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-21 04:44:40 +0000 (Fri, 21 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2023-26048", "CVE-2023-26049");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Multiple Vulnerabilities (GHSA-qw69-rqj8-6qw8, GHSA-p26g-97m4-6q7c) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-26048: OutOfMemoryError for large multipart without filename read via
  request.getParameter()

  - CVE-2023-26049: Cookie parsing of quoted values can exfiltrate values from other cookies");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.4.50 and prior, version 10.0.x through
  10.0.13 and 11.0.x through 11.0.13.");

  script_tag(name:"solution", value:"Update to version 9.4.51, 10.0.14, 11.0.14 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-qw69-rqj8-6qw8");
  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-p26g-97m4-6q7c");

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

if (version_is_less(version: version, test_version: "9.4.51")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.51", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
