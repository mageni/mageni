# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:asustor:adm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150890");
  script_version("2023-08-24T05:06:01+0000");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-21 04:55:06 +0000 (Mon, 21 Aug 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-2910", "CVE-2023-3697", "CVE-2023-3698", "CVE-2023-3699",
                "CVE-2023-4475");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ASUSTOR ADM Multiple Vulnerabilities (AS-2023-009, AS-2023-010, AS-2023-011, AS-2023-012)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_asustor_adm_http_detect.nasl");
  script_mandatory_keys("asustor/adm/detected");

  script_tag(name:"summary", value:"ASUSTOR ADM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-2910: Command injection

  - CVE-2023-3697, CVE-2023-3698: Multiple directory traversals

  - CVE-2023-3699: Improper privilege management

  - CVE-2023-4475: Arbitrary file movement");

  script_tag(name:"affected", value:"ASUSTOR ADM version 4.0.6.RIS1 and prior and 4.1.0 through
  4.2.2.RI61.");

  script_tag(name:"solution", value:"Update to version 4.2.3.RK91 or later.");

  script_xref(name:"URL", value:"https://www.asustor.com/security/security_advisory_detail?id=27");
  script_xref(name:"URL", value:"https://www.asustor.com/security/security_advisory_detail?id=28");
  script_xref(name:"URL", value:"https://www.asustor.com/security/security_advisory_detail?id=29");
  script_xref(name:"URL", value:"https://www.asustor.com/security/security_advisory_detail?id=30");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (revcomp(a: version, b: "4.0.6.ris1") <= 0) {
  report = report_fixed_ver(installed_version: toupper(version), fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "4.1.0") >= 0) && (revcomp(a: version, b: "4.2.2.ri61") <= 0)) {
  report = report_fixed_ver(installed_version: toupper(version), fixed_version: "4.2.3.RK91");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
