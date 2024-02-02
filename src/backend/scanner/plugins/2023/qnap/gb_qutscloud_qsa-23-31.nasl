# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qutscloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151257");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-07 03:08:24 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-15 16:28:00 +0000 (Wed, 15 Nov 2023)");

  script_cve_id("CVE-2023-23368");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTScloud OS Command Injection Vulnerability (QSA-23-31)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qutscloud/detected");

  script_tag(name:"summary", value:"QNAP QuTScloud is prone to an OS command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An OS command injection vulnerability has been reported to
  affect several QNAP operating system versions. If exploited, the vulnerability could allow remote
  attackers to execute commands via a network.");

  script_tag(name:"affected", value:"QNAP QuTScloud c5.0.x.");

  script_tag(name:"solution", value:"Update to version c5.0.1.2374 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-31");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "c5.0.0", test_version_up: "c5.0.1.2374")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "c5.0.1.2374");
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
