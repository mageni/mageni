# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832747");
  script_version("2023-12-20T12:22:41+0000");
  script_cve_id("CVE-2023-42874", "CVE-2023-42919", "CVE-2023-42894", "CVE-2023-42901",
                "CVE-2023-42902", "CVE-2023-42912", "CVE-2023-42903", "CVE-2023-42904",
                "CVE-2023-42905", "CVE-2023-42906", "CVE-2023-42907", "CVE-2023-42908",
                "CVE-2023-42909", "CVE-2023-42910", "CVE-2023-42911", "CVE-2023-42926",
                "CVE-2023-42882", "CVE-2023-42881", "CVE-2023-42924", "CVE-2023-42884",
                "CVE-2023-45866", "CVE-2023-42900", "CVE-2023-42886", "CVE-2023-42927",
                "CVE-2023-42922", "CVE-2023-42898", "CVE-2023-42899", "CVE-2023-42891",
                "CVE-2023-42914", "CVE-2020-19185", "CVE-2020-19186", "CVE-2020-19187",
                "CVE-2020-19188", "CVE-2020-19189", "CVE-2020-19190", "CVE-2023-42842",
                "CVE-2023-42932", "CVE-2023-5344", "CVE-2023-42890", "CVE-2023-42883");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 19:14:00 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-14 15:40:39 +0530 (Thu, 14 Dec 2023)");
  script_name("Apple MacOSX Security Update (HT214036)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Existence of vulnerable code.

  - Improper memory handling.

  - Improper input validation.

  - Improper checks.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct spoofing, arbitrary code execution, information disclosure, and
  conduct DoS attacks on an affected system.");

  script_tag(name:"affected", value:"Apple macOS Sonoma prior to version 14.2");

  script_tag(name:"solution", value:"Upgrade to version 14.2 for macOS Sonoma.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214036");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^14\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"14.2")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"14.2");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
