# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832148");
  script_version("2023-06-28T05:05:22+0000");
  script_cve_id("CVE-2023-32434");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:22 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-27 15:57:06 +0530 (Tue, 27 Jun 2023)");
  script_name("Apple MacOSX Security Update(HT213809)");

  script_tag(name:"summary", value:"An integer overflow vulnerability in Apple macOS Big Sur");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an integer overflow
  when validating the input.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability allow remote attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur prior to version 11.7.18");

  script_tag(name:"solution", value:"Upgrade to version 11.5 for macOS Big Sur 11.7.18");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213809");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^11\.");
  exit(0);
}
include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^11\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_is_less(version:osVer, test_version:"11.7.18"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.7.18");
  security_message(data:report);
  exit(0);
}

exit(99);
