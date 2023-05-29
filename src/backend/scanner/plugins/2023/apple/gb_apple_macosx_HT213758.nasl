# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826991");
  script_version("2023-05-22T12:17:59+0000");
  script_cve_id("CVE-2023-28204", "CVE-2023-32352", "CVE-2023-32355", "CVE-2023-32357",
                "CVE-2023-32360", "CVE-2023-32363", "CVE-2023-32367", "CVE-2023-32368",
                "CVE-2023-32369", "CVE-2023-32371", "CVE-2023-32372", "CVE-2023-32373",
                "CVE-2023-32375", "CVE-2023-32376", "CVE-2023-32380", "CVE-2023-32382",
                "CVE-2023-32384", "CVE-2023-32385", "CVE-2023-32386", "CVE-2023-32387",
                "CVE-2023-32388", "CVE-2023-32389", "CVE-2023-32390", "CVE-2023-32391",
                "CVE-2023-32392", "CVE-2023-32394", "CVE-2023-32395", "CVE-2023-32397",
                "CVE-2023-32398", "CVE-2023-32399", "CVE-2023-32400", "CVE-2023-32402",
                "CVE-2023-32403", "CVE-2023-32404", "CVE-2023-32405", "CVE-2023-32407",
                "CVE-2023-32408", "CVE-2023-32409", "CVE-2023-32410", "CVE-2023-32411",
                "CVE-2023-32412", "CVE-2023-32413", "CVE-2023-32414", "CVE-2023-32415",
                "CVE-2023-32420", "CVE-2023-32422", "CVE-2023-32423");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-05-22 12:17:59 +0000 (Mon, 22 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-22 11:55:29 +0530 (Mon, 22 May 2023)");
  script_name("Apple MacOSX Security Update (HT213758)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to miltiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper state and memory management.

  - Improper permissions checks and private data redaction.

  - Improper handling of temporary files.

  - Improper entitlements.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, bypass security restrictions and disclose
  sensitive information on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Ventura prior to
  version 13.4.");

  script_tag(name:"solution", value:"Upgrade to version 13.4 for macOS Ventura.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213758");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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
if(!osVer || osVer !~ "^13\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_is_less(version:osVer, test_version:"13.4"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.4");
  security_message(data:report);
  exit(0);
}

exit(99);
