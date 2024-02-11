# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151645");
  script_version("2024-02-07T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-02-07 05:05:18 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-05 05:22:28 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-06 20:10:07 +0000 (Tue, 06 Feb 2024)");

  script_cve_id("CVE-2023-41273", "CVE-2023-41274", "CVE-2023-41275", "CVE-2023-41276",
                "CVE-2023-41277", "CVE-2023-41278", "CVE-2023-41279", "CVE-2023-41280");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-23-38)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-41273: A heap-based buffer overflow could allow authenticated administrators to
  execute code via a network.

  - CVE-2023-41274: A NULL pointer dereference could allow authenticated administrators to launch a
  denial of service (DoS) attack via a network.

  - CVE-2023-41275, CVE-2023-41276, CVE-2023-41277, CVE-2023-41278, CVE-2023-41279, CVE-2023-41280:
  Multiple buffer copies without checking size of input could allow authenticated administrators to
  execute code via a network.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h5.1.x.");

  script_tag(name:"solution", value:"Update to version h5.1.2.2534 build 20230927 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-38");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.1") {
  if (version_is_less(version: version, test_version: "h5.1.2.2534")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.2.2534", fixed_build: "20230927");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.1.2.2534") &&
     (!build || version_is_less(version: build, test_version: "20230927"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.2.2534", fixed_build: "20230927");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
