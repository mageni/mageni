# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150851");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-14 03:18:27 +0000 (Mon, 14 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-39417");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 11.x < 11.21, 12.x < 12.16, 13.x < 13.12, 14.x < 14.9, 15.x < 15.4 SQLi Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An extension script is vulnerable if it uses @extowner@,
  @extschema@, or @extschema:...@ inside a quoting construct. No bundled extension is vulnerable.");

  script_tag(name:"affected", value:"PostgreSQL versions 11.x prior to 11.21, 12.x prior to 12.16,
  13.x prior to 13.12, 14.x prior to 14.9 and 15.x prior to 15.4.");

  script_tag(name:"solution", value:"Update to version 11.21, 12.16, 13.12, 14.9, 15.4 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-154-149-1312-1216-1121-and-postgresql-16-beta-3-released-2689/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2023-39417/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "11.0", test_version_up: "11.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "12.0", test_version_up: "12.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "13.0", test_version_up: "13.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.0", test_version_up: "15.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
