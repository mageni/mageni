# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832152");
  script_version("2023-07-25T05:05:58+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-37450");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-11 13:18:19 +0530 (Tue, 11 Jul 2023)");
  script_name("Apple Safari Security Update (HT213826)");

  script_tag(name:"summary", value:"Apple Safari Arbitrary Code Execution Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists when processing web
  content may lead to arbitrary code execution. Apple is aware of a report
  that this issue may have been actively exploited.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Apple Safari versions before 16.5.2");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 16.5.2 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213826");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || (osVer !~ "^12\." && osVer !~ "^11\.") || "Mac OS X" >!< osName)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"16.5.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"16.5.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
