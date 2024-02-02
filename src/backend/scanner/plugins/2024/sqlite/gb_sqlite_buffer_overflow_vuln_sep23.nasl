# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sqlite:sqlite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126572");
  script_version("2024-01-18T05:07:09+0000");
  script_tag(name:"last_modification", value:"2024-01-18 05:07:09 +0000 (Thu, 18 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-11 10:28:38 +0000 (Thu, 11 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-08 17:46:00 +0000 (Mon, 08 Jan 2024)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-7104");

  script_name("SQLite < 3.43.1 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This issue affects the function sessionReadRecord of the file
  ext/session/sqlite3session.c of the component make alltest Handler. The manipulation leads to
  heap-based buffer overflow.");

  script_tag(name:"affected", value:"SQLite prior to version 3.43.1.");

  script_tag(name:"solution", value:"Update to version 3.43.1 or later.");

  script_xref(name:"URL", value:"https://sqlite.org/forum/forumpost/5bcbf4571c");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.43.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.43.1", install_path: location);
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
