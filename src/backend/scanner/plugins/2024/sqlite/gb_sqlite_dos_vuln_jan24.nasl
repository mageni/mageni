# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sqlite:sqlite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126591");
  script_version("2024-01-25T14:38:15+0000");
  script_tag(name:"last_modification", value:"2024-01-25 14:38:15 +0000 (Thu, 25 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-23 09:28:38 +0000 (Tue, 23 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-24 14:14:00 +0000 (Wed, 24 Jan 2024)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2024-0232");

  script_name("SQLite < 3.43.2 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A heap use-after-free issue has been identified in the
  jsonParseAddNodeArray() function in sqlite3.c.");

  script_tag(name:"impact", value:"This flaw allows a local attacker to leverage a victim to pass
  specially crafted malicious input to the application, potentially causing a crash and leading to
  a denial of service.");

  script_tag(name:"affected", value:"SQLite prior to version 3.43.2.");

  script_tag(name:"solution", value:"Update to version 3.43.2 or later.");

  script_xref(name:"URL", value:"https://sqlite.org/forum/forumpost/4aa381993a");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.43.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.43.2", install_path: location);
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
