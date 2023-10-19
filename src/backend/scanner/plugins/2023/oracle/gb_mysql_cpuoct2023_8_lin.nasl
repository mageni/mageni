# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151225");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-18 05:42:07 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2023-22059", "CVE-2023-22097", "CVE-2023-22066", "CVE-2023-22068",
                "CVE-2023-22114", "CVE-2023-22032", "CVE-2023-22070", "CVE-2023-22103",
                "CVE-2023-22078");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.x <= 8.0.34, 8.1.0 Security Update (cpuoct2023) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 8.x through 8.0.34 and 8.1.0.");

  script_tag(name:"solution", value:"Update to version 8.0.35, 8.1.1 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2023.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuoct2023");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.35", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "8.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
