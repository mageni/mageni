# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170691");
  script_version("2023-11-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-11-22 05:05:24 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-13 12:32:02 +0000 (Mon, 13 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-31467", "CVE-2023-32779");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 7.21, 8.x < 8.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"ILIAS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-32779 / 37244: [Init] Possible authentication bypass

  - CVE-2023-31467 / 37242: [Web Access Checker]: Path traversal / local file inclusion in
  WebAccessChecker");

  script_tag(name:"affected", value:"ILIAS prior to version 7.21 and 8.x prior to 8.2.");

  script_tag(name:"solution", value:"Update to version 7.21, 8.2 or later.");

  script_xref(name:"URL", value:"https://docu.ilias.de/ilias.php?baseClass=illmpresentationgui&cmd=layout&ref_id=35&obj_id=141694");
  script_xref(name:"URL", value:"https://docu.ilias.de/ilias.php?baseClass=illmpresentationgui&cmd=layout&ref_id=35&obj_id=141703");

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

if (version_is_less(version: version, test_version: "7.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
