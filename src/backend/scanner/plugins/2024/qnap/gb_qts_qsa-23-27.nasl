# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151479");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-09 03:06:49 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-10 16:54:00 +0000 (Wed, 10 Jan 2024)");

  script_cve_id("CVE-2023-45039", "CVE-2023-45040", "CVE-2023-45041", "CVE-2023-45042",
                "CVE-2023-45043", "CVE-2023-45044");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (QSA-23-27)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-45039, CVE-2023-45040, CVE-2023-45041, CVE-2023-45042, CVE-2023-45043, CVE-2023-45044:
  Multiple buffer copy without checking size of input vulnerabilities have been reported to affect
  certain QNAP operating system versions. If exploited, the vulnerabilities could allow
  authenticated administrators to execute code via a network.");

  script_tag(name:"affected", value:"QNAP QTS version 5.1.x.");

  script_tag(name:"solution", value:"Update to version 5.1.4.2596 build 20231128 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-27");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^5\.1") {
  if (version_is_less(version: version, test_version:"5.1.4.2596")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.1.4.2596", fixed_build: "20231128");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.1.4.2596") &&
     (!build || version_is_less(version: build, test_version: "20231128"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "5.1.4.2596", fixed_build: "20231128");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
