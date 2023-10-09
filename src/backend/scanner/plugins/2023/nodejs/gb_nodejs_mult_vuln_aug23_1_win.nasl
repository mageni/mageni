# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170537");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-10 13:51:31 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-32002", "CVE-2023-32006", "CVE-2023-32559", "CVE-2023-2975",
                "CVE-2023-3446", "CVE-2023-3817");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 16.x < 16.20.2, 18.x < 18.17.1, 20.x < 20.5.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_detect_win.nasl");
  script_mandatory_keys("Nodejs/Win/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-32002: Permissions policies can be bypassed via Module._load

  - CVE-2023-32006: Permissions policies can impersonate other modules in using
  module.constructor.createRequire()

  - CVE-2023-32559: Permissions policies can be bypassed via process.binding

  - CVE-2023-2975, CVE-2023-3446, CVE-2023-3817: OpenSSL security updates");

  script_tag(name:"affected", value:"Node.js version 16.x through 16.20.1, 18.x through 18.17.0 and
  20.x through 20.5.0.");

  script_tag(name:"solution", value:"Update to version 16.20.2, 18.17.1, 20.5.1 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/august-2023-security-releases");

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

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.20.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.20.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "18.0", test_version_up: "18.17.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.17.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "20.0", test_version_up: "20.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.5.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
