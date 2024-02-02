# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832608");
  script_version("2024-01-29T05:05:18+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-40417", "CVE-2023-40451", "CVE-2023-41074", "CVE-2023-35074",
                "CVE-2023-41993", "CVE-2023-40414", "CVE-2023-40385", "CVE-2023-42833");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-29 05:05:18 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-25 16:47:00 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-10-27 13:07:18 +0530 (Fri, 27 Oct 2023)");
  script_name("Apple Safari Security Update (HT213941)");

  script_tag(name:"summary", value:"Apple Safari is multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Improper memory handling, state management, checks.

  - Improper iframe sandbox enforcement.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow attackers to conduct arbitrary code execution and spoofing attack.");

  script_tag(name:"affected", value:"Apple Safari versions before 17");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 17 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213941");
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

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || (osVer !~ "^12\." && osVer !~ "^13\.") || "Mac OS X" >!< osName)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
safVer = infos["version"];
safPath = infos["location"];

if(version_is_less(version:safVer, test_version:"17")) {
  report = report_fixed_ver(installed_version:safVer, fixed_version:"17", install_path:safPath);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
