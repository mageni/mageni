# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:openjdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104862");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-19 05:46:25 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2023-22045", "CVE-2023-22049");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle OpenJDK 8.x, 11.x, 17.x, 20.x Multiple Vulnerabilities (Jul 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_openjdk_detect.nasl");
  script_mandatory_keys("openjdk/detected");

  script_tag(name:"summary", value:"Oracle OpenJDK is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Affected components:

  - CVE-2023-22045: hotspot/compiler

  - CVE-2023-22049: core-libs/java.io

  See the referenced CVEs for more details on the flaws.");

  script_tag(name:"affected", value:"Oracle OpenJDK versions 8, 11, 17 and 20.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://openjdk.org/groups/vulnerability/advisories/2023-07-18");
  script_xref(name:"URL", value:"https://mail.openjdk.org/pipermail/vuln-announce/2023-July/000020.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.8.0", test_version2: "1.8.0.372")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.0.382 (8u382)", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0.0", test_version2: "11.0.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "17.0.0", test_version2: "17.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "20.0.0", test_version2: "20.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
