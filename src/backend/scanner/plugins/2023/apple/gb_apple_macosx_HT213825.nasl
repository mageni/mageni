# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832151");
  script_version("2023-07-25T05:05:58+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-37450");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-11 12:24:50 +0530 (Tue, 11 Jul 2023)");
  script_name("Apple MacOSX Security Update (HT213825)");

  script_tag(name:"summary", value:"Apple Mac OS X Arbitrary Code Execution Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when processing web
  content may lead to arbitrary code execution. Apple is aware of a report
  that this issue may have been actively exploited.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Apple macOS Ventura prior to version 13.4.1 build 22F770820b");

  script_tag(name:"solution", value:"Upgrade to version 13.4.1 build 22F770820b for macOS Ventura.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213825");
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

buildVer = get_kb_item("ssh/login/osx_build");
if(version_in_range(version:osVer, test_version:"13", test_version2:"13.4.0")){
  fix = "Upgrade to latest OS release and apply patch from vendor";
}

else if(osVer == "13.4.1"){
  if(version_is_less(version:buildVer, test_version:"22F770820b")){
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

if(fix){
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
