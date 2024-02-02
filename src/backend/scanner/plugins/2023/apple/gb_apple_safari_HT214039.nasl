# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832746");
  script_version("2023-12-15T16:10:08+0000");
  script_cve_id("CVE-2023-42890", "CVE-2023-42883");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 18:10:00 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-14 14:44:50 +0530 (Thu, 14 Dec 2023)");
  script_name("Apple Safari Security Update (HT214039)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an improper
  handling of memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution and denial-of-service attacks on an affected
  system.");

  script_tag(name:"affected", value:"Apple Safari versions before 17.2 on
  macOS Monterey and macOS Ventura.");

  script_tag(name:"solution", value:"Upgrade to version 17.2 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214039");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || (osVer !~ "^13\." && osVer !~ "^12\."))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"17.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
