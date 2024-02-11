# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151647");
  script_version("2024-02-07T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-02-07 05:05:18 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-05 05:35:47 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-06 20:18:26 +0000 (Tue, 06 Feb 2024)");

  script_cve_id("CVE-2023-45026", "CVE-2023-45027", "CVE-2023-45028", "CVE-2023-47566",
                "CVE-2023-48795", "CVE-2023-50359");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-24-02, QSA-24-04, QSA-24-06, QSA-24-07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-45026, CVE-2023-45027: Multiple path traversals could allow authenticated
  administrators to read the contents of unexpected files and expose sensitive data via a network.

  - CVE-2023-45028: An uncontrolled resource consumption vulnerability could allow authenticated
  administrators to launch a denial of service (DoS) attack via a network.

  - CVE-2023-47566: An OS command injection has been reported to affect several QNAP operating
  system versions. If exploited, the vulnerability could allow authenticated administrators to
  execute commands via a network.

  - CVE-2023-48795: A vulnerability in OpenSSH has been reported to affect certain QNAP operating
  system versions.

  - CVE-2023-50359: An unchecked return value has been reported to affect certain QNAP operating
  system versions. If exploited, the vulnerability could allow local authenticated administrators
  to place the system in a state that could lead to a crash or other unintended behaviors via
  unspecified vectors.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h5.1.x.");

  script_tag(name:"solution", value:"Update to version h5.1.5.2647 build 20240118 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-02");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-04");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-06");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-07");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.1") {
  if (version_is_less(version: version, test_version: "h5.1.5.2647")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.5.2647", fixed_build: "20240118");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.1.5.2647") &&
     (!build || version_is_less(version: build, test_version: "20240118"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.5.2647", fixed_build: "20240118");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
