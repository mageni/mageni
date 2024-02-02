# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832612");
  script_version("2023-11-07T05:06:14+0000");
  script_cve_id("CVE-2023-30774", "CVE-2023-40444", "CVE-2023-41072", "CVE-2023-42857",
                "CVE-2023-40449", "CVE-2023-41989", "CVE-2023-42854", "CVE-2023-40413",
                "CVE-2023-42844", "CVE-2023-40416", "CVE-2023-40423", "CVE-2023-38403",
                "CVE-2023-42849", "CVE-2023-42850", "CVE-2023-42861", "CVE-2023-40408",
                "CVE-2023-40405", "CVE-2023-42856", "CVE-2023-40404", "CVE-2023-42847",
                "CVE-2023-42845", "CVE-2023-42841", "CVE-2023-41977", "CVE-2023-42438",
                "CVE-2023-41982", "CVE-2023-41997", "CVE-2023-41988", "CVE-2023-40421",
                "CVE-2023-42842", "CVE-2023-4733", "CVE-2023-4734", "CVE-2023-4735",
                "CVE-2023-4736", "CVE-2023-4738", "CVE-2023-4750", "CVE-2023-4751",
                "CVE-2023-4752", "CVE-2023-4781", "CVE-2023-41254", "CVE-2023-40447",
                "CVE-2023-41976", "CVE-2023-42852", "CVE-2023-41983", "CVE-2023-41975");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-07 05:06:14 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-02 18:25:00 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-27 13:07:18 +0530 (Fri, 27 Oct 2023)");
  script_name("Apple MacOSX Security Update (HT213984)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Existence of vulnerable code.

  - Improper checks.

  - Improper handling of caches.

  - Existence of vulnerable code.

  - An improper input validation.

  - An improper memory handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct spoofing, arbitrary code execution, denial of service, information disclosure.");

  script_tag(name:"affected", value:"Apple macOS Sonoma prior to version 14.1");

  script_tag(name:"solution", value:"Upgrade to version 14.1 for macOS Sonoma.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213984");
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

if(version_is_less(version:osVer, test_version:"14.1")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"14.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
