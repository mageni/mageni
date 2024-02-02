# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pi-hole:web_interface";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114201");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-30 16:25:15 +0000 (Thu, 30 Nov 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 15:45:00 +0000 (Fri, 15 Jul 2022)");

  script_cve_id("CVE-2022-31029");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pi-hole Web Interface <= 5.12 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pi-hole_http_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"The Pi-hole Web Interface (previously AdminLTE) is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In affected versions inserting code like
  <script>alert('XSS')</script> in the field marked with 'Domain to look for' and hitting
  <kbd>enter</kbd> (or clicking on any of the buttons) will execute the script. The user must be
  logged in to use this vulnerability. Usually only administrators have login access to pi-hole,
  minimizing the risks.");

  script_tag(name:"affected", value:"Pi-hole Web Interface (previously AdminLTE) versions 5.12 and
  prior.");

  script_tag(name:"solution", value:"Update to version 5.13 or later.");

  script_xref(name:"URL", value:"https://github.com/pi-hole/web/security/advisories/GHSA-cfr5-rqm5-9vhp");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "5.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
