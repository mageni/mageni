# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832338");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2023-35983", "CVE-2023-28319", "CVE-2023-28320", "CVE-2023-28321",
                "CVE-2023-28322", "CVE-2023-36854", "CVE-2023-32418", "CVE-2023-32381",
                "CVE-2023-32433", "CVE-2023-35993", "CVE-2023-38606", "CVE-2023-32441",
                "CVE-2023-38565", "CVE-2023-38593", "CVE-2023-2953", "CVE-2023-38259",
                "CVE-2023-38602", "CVE-2023-32443");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-25 15:52:56 +0530 (Tue, 25 Jul 2023)");
  script_name("Apple MacOSX Security Update (HT213845)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper usage and handling of curl.

  - An improper processing of files.

  - A use-after-free in memory management.

  - An improper bounds checking and input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  execute arbitrary code with kernel privileges on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur versions 11.x before
  11.7.9.");

  script_tag(name:"solution", value:"Upgrade to version 11.7.9 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213845");
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
if(!osVer || osVer !~ "^11\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"11.7.9")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.7.9");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);
