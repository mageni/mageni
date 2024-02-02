# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832613");
  script_version("2024-01-22T05:07:31+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-41064");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-22 05:07:31 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-12 13:09:00 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-10-27 13:07:18 +0530 (Fri, 27 Oct 2023)");
  script_name("Apple MacOSX Security Updates (HT213906)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a buffer overflow issue resulting
  from improper memory handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Ventura versions prior to
  version 13.5.2.");

  script_tag(name:"solution", value:"Upgrade to version 13.5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213906");
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
if(!osVer || osVer !~ "^13\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"13.5.2")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.5.2");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
