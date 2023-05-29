# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826989");
  script_version("2023-05-22T12:17:59+0000");
  script_cve_id("CVE-2023-27945", "CVE-2023-28181", "CVE-2023-28191", "CVE-2023-32352",
                "CVE-2023-32355", "CVE-2023-32357", "CVE-2023-32360", "CVE-2023-32369",
                "CVE-2023-32380", "CVE-2023-32382", "CVE-2023-32384", "CVE-2023-32386",
                "CVE-2023-32387", "CVE-2023-32388", "CVE-2023-32392", "CVE-2023-32395",
                "CVE-2023-32397", "CVE-2023-32398", "CVE-2023-32403", "CVE-2023-32405",
                "CVE-2023-32407", "CVE-2023-32410", "CVE-2023-32411", "CVE-2023-32412",
                "CVE-2023-32413");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-05-22 12:17:59 +0000 (Mon, 22 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-22 11:55:29 +0530 (Mon, 22 May 2023)");
  script_name("Apple MacOSX Security Update (HT213760)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper redaction of sensitive information.

  - An improper entitlements.

  - An improper handling of temporary files.

  - An improper state and memory management.

  - An improper bounds checking and input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  disclose sensitive information, escalate privileges and execute arbitrary code
  with kernel privileges on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur versions 11.x before
  11.7.7.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Big Sur version
  11.7.7 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213760");
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
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^11\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_is_less(version:osVer, test_version:"11.7.7"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.7.7");
  security_message(data:report);
  exit(0);
}
exit(99);
