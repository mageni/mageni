# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:openjdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114280");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-17 07:49:08 +0000 (Wed, 17 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 23:12:00 +0000 (Tue, 16 Jan 2024)");

  script_cve_id("CVE-2024-20918", "CVE-2024-20919", "CVE-2024-20921", "CVE-2024-20945",
                "CVE-2024-20952");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle OpenJDK 8.x, 11.x, 17.x, 21.x Multiple Vulnerabilities (Jan 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_openjdk_detect.nasl");
  script_mandatory_keys("openjdk/detected");

  script_tag(name:"summary", value:"Oracle OpenJDK is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Affected components:

  - CVE-2024-20918: hotspot/compiler

  - CVE-2024-20919: hotspot/runtime

  - CVE-2024-20921: hotspot/compiler

  - CVE-2024-20945: security-libs/javax.xml.crypto

  - CVE-2024-20952: security-libs/java.security

  See the referenced CVEs for more details on the flaws.");

  script_tag(name:"affected", value:"Oracle OpenJDK versions 8, 11, 17 and 21.

  Note: The vendor is only evaluating the affected status of supported versions but EOL versions
  like 9, 12 or 18 in between the affected versions are also assumed to be affected.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://openjdk.org/groups/vulnerability/advisories/2024-01-16");
  script_xref(name:"URL", value:"https://mail.openjdk.org/pipermail/vuln-announce/2024-January/000022.html");

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

if (version_in_range(version: version, test_version: "1.8.0", test_version2: "1.8.0.392")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.0.402 (8u402)", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "11.0.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "17.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "18.0", test_version2: "21.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
