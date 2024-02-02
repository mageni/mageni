# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832738");
  script_version("2023-12-15T16:10:08+0000");
  script_cve_id("CVE-2023-42919", "CVE-2023-42894", "CVE-2023-42886", "CVE-2023-42922",
                "CVE-2023-42899", "CVE-2023-42891", "CVE-2023-42914", "CVE-2020-19185",
                "CVE-2020-19186", "CVE-2020-19187", "CVE-2020-19188", "CVE-2020-19189",
                "CVE-2020-19190", "CVE-2023-42932", "CVE-2023-5344");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-14 14:07:00 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 16:53:41 +0530 (Wed, 13 Dec 2023)");
  script_name("Apple MacOSX Security Update (HT214037)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A privacy issue was addressed with improved private data redaction for log entries.

  - An out-of-bounds read was addressed with improved bounds checking.

  - An authentication issue was addressed with improved state management.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, disclose sensitive information and conduct
  denial of service attacks on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Monterey versions 12.x before
  12.7.2.");

  script_tag(name:"solution", value:"Upgrade to version 12.7.2 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214037");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName) {
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^12\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"12.7.2")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"12.7.2");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

