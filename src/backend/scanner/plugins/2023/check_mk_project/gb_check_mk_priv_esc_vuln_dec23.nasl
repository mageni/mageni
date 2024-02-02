# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124491");
  script_version("2023-12-20T12:22:41+0000");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-15 08:03:05 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-18 17:31:00 +0000 (Mon, 18 Dec 2023)");

  script_cve_id("CVE-2023-31210");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk 2.2.0p10 < 2.2.0p17 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In order to monitor livestatus from running sites on a host the
  Checkmk agent uses unixcat that is part of Checkmk. Since the binary is linked to libraries that
  are also part of Checkmk and may differ from the libraries of the operating system, calling
  unixcat outside of the scope of a site could result to errors due to version mismatches in these
  libraries.");

  script_tag(name:"affected", value:"Checkmk version 2.2.0p10.x prior to 2.2.0p17.");

  script_tag(name:"solution", value:"Update to version 2.2.0p17, 2.3.0b1 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/16226");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.2.0p10.0", test_version_up: "2.2.0p17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.0p17, 2.3.0b1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
