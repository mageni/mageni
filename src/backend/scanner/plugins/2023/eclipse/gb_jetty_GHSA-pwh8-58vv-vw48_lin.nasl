# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151005");
  script_version("2023-09-20T05:05:13+0000");
  script_tag(name:"last_modification", value:"2023-09-20 05:05:13 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-19 04:57:16 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2023-41900");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty OpenID Vulnerability (GHSA-pwh8-58vv-vw48) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a vulnerability in
  OpenIdAuthenticator.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If a Jetty OpenIdAuthenticator uses the optional nested
  LoginService, and that LoginService decides to revoke an already authenticated user, then the
  current request will still treat the user as authenticated. The authentication is then cleared
  from the session and subsequent requests will not be treated as authenticated.

  So a request on a previously authenticated session could be allowed to bypass authentication
  after it had been rejected by the LoginService.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.4.21 through 9.4.51, 10.0.0 through
  10.0.15 and 11.0.0 through 11.0.15.");

  script_tag(name:"solution", value:"Update to version 9.4.52, 10.0.16, 11.0.16 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-pwh8-58vv-vw48");

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

if (version_in_range_exclusive(version: version, test_version_lo: "9.4.21", test_version_up: "9.4.52")) {
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
