# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151002");
  script_version("2023-09-20T05:05:13+0000");
  script_tag(name:"last_modification", value:"2023-09-20 05:05:13 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-19 04:46:18 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2023-40167");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty HTTP Header Vulnerability (GHSA-hmr7-m48g-48f6) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to an HTTP header vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jetty accepts the '+' character proceeding the content-length
  value in a HTTP/1 header field. This is more permissive than allowed by the RFC and other servers
  routinely reject such requests with 400 responses. There is no known exploit scenario, but it is
  conceivable that request smuggling could result if jetty is used in combination with a server
  that does not close the connection after sending such a 400 response.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.0.0 through 9.4.51, 10.0.0 through
  10.0.15, 11.0.0 through 11.0.15 and version 12.0.0.");

  script_tag(name:"solution", value:"Update to version 9.4.52, 10.0.16, 11.0.16, 12.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-hmr7-m48g-48f6");

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

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0", test_version_up: "9.4.52")) {
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

if (version_is_equal(version: version, test_version: "12.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
