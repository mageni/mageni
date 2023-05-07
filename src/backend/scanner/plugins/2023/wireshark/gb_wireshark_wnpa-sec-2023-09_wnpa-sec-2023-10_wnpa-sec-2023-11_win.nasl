# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832054");
  script_version("2023-05-04T09:51:03+0000");
  script_cve_id("CVE-2023-1992", "CVE-2023-1993", "CVE-2023-1994");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"creation_date", value:"2023-04-21 12:28:37 +0530 (Fri, 21 Apr 2023)");
  script_name("Wireshark Security Multiple DoS Vulnerabilities April23 - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An unexpected crash in RPCoRDMA dissector crash.

  - LISP dissector large loop crash in Wireshark.

  - GQUIC dissector crash in Wireshark.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation may allow
  remote attackers to perform denial of service on an affected system.");

  script_tag(name:"affected", value:"Wireshark versions 4.0.0 to 4.0.4, 3.6.0 to 3.6.12.");

  script_tag(name:"solution", value:"Update to version 4.0.5 or 3.6.13 or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-09.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-10.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-11.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}
include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"3.6.0", test_version2:"3.6.12")) {
    fix = "3.6.13";
}
else if(version_in_range(version:vers, test_version:"4.0.0.", test_version2:"4.0.4")) {
  fix = "4.0.5";
}
if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
