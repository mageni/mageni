# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:asustor:adm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150889");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-21 04:37:40 +0000 (Mon, 21 Aug 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-30770");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ASUSTOR ADM Buffer Overflow Vulnerability (AS-2023-003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_asustor_adm_http_detect.nasl");
  script_mandatory_keys("asustor/adm/detected");

  script_tag(name:"summary", value:"ASUSTOR ADM is prone to a stack-based buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stack-based buffer overflow vulnerability was found in the
  ASUSTOR Data Master (ADM) due to the lack of data size validation.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to execute arbitrary
  code.");

  script_tag(name:"affected", value:"ASUSTOR ADM version 4.0.6.REG2 and prior and 4.1.0 through
  4.2.0.RE71.");

  script_tag(name:"solution", value:"Update to version 4.0.6.RIS1, 4.2.1.RGE2 or later.");

  script_xref(name:"URL", value:"https://www.asustor.com/security/security_advisory_detail?id=21");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (revcomp(a: version, b: "4.0.6.reg2") <= 0) {
  report = report_fixed_ver(installed_version: toupper(version), fixed_version: "4.0.6.RIS1");
  security_message(port: 0, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "4.1.0") >= 0) && (revcomp(a: version, b: "4.2.0.re71") <= 0)) {
  report = report_fixed_ver(installed_version: toupper(version), fixed_version: " 4.2.1.RGE2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
