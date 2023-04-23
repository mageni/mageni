# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:openjdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104691");
  script_version("2023-04-19T10:08:55+0000");
  script_tag(name:"last_modification", value:"2023-04-19 10:08:55 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-19 07:23:18 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-21930", "CVE-2023-21937", "CVE-2023-21938", "CVE-2023-21939",
                "CVE-2023-21967", "CVE-2023-21968");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle OpenJDK Multiple Vulnerabilities (Apr 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_openjdk_detect.nasl");
  script_mandatory_keys("openjdk/detected");

  script_tag(name:"summary", value:"Oracle OpenJDK is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Affected components:

  - CVE-2023-21930: security-libs/javax.net.ssl

  - CVE-2023-21937: core-libs/java.net

  - CVE-2023-21938: core-libs/java.lang

  - CVE-2023-21939: client-libs/javax.swing

  - CVE-2023-21967: security-libs/javax.net.ssl

  - CVE-2023-21968: core-libs/java.nio

  See the referenced CVEs for more details on the flaws.");

  script_tag(name:"affected", value:"Oracle OpenJDK versions 8, 11, 17 and 20.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://openjdk.org/groups/vulnerability/advisories/2023-04-18");
  script_xref(name:"URL", value:"https://mail.openjdk.org/pipermail/vuln-announce/2023-April/000019.html");

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

if (version_in_range(version: version, test_version: "1.8.0", test_version2: "1.8.0.362")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.0.372 (8u372)", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0.0", test_version2: "11.0.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "17.0.0", test_version2: "17.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "20.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
