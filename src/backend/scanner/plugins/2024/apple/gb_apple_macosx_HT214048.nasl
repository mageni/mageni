# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832761");
  script_version("2024-01-18T05:07:09+0000");
  script_cve_id("CVE-2023-42940");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-01-18 05:07:09 +0000 (Thu, 18 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-04 14:56:00 +0000 (Thu, 04 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-08 14:54:24 +0530 (Mon, 08 Jan 2024)");
  script_name("Apple MacOSX Security Update (HT214048)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to an unspecified
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a session rendering
  issue in Apple macOS Sonoma.");

  script_tag(name:"impact", value:"Successful exploitation will allow users who
  shares their screen to share the incorrect content unintentionally.");

  script_tag(name:"affected", value:"Apple macOS Sonoma prior to version 14.2.1");

  script_tag(name:"solution", value:"Upgrade to version 14.2.1 for macOS Sonoma.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214048");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:osVer, test_version:"14.2.1")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"14.2.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
