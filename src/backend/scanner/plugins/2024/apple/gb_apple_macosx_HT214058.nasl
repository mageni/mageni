# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832799");
  script_version("2024-01-29T05:05:18+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-23212", "CVE-2023-42937", "CVE-2023-40528", "CVE-2023-38545",
                "CVE-2023-38039", "CVE-2023-38546", "CVE-2023-42915", "CVE-2024-23224",
                "CVE-2023-42888", "CVE-2023-42935", "CVE-2024-23207", "CVE-2023-42887",
                "CVE-2024-23222");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-29 05:05:18 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-25 13:24:00 +0000 (Wed, 25 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-01-23 18:16:35 +0530 (Tue, 23 Jan 2024)");
  script_name("Apple MacOSX Security Update (HT214058)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A privacy issue was addressed with improved private data redaction for log entries.

  - The issue was addressed with improved memory handling.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, information disclosure and also to bypass
  certain privacy preferences on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Ventura prior to
  version 13.6.4.");

  script_tag(name:"solution", value:"Upgrade to version 13.6.4 for macOS Ventura.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214058");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^13\.");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^13\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"13.6.4")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.6.4");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
