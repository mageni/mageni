# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832107");
  script_version("2023-04-18T10:10:05+0000");
  script_cve_id("CVE-2023-29532", "CVE-2023-29533", "CVE-2023-29535", "CVE-2023-29536",
                "CVE-2023-29539", "CVE-2023-29542", "CVE-2023-29545", "CVE-2023-1945",
                "CVE-2023-29548", "CVE-2023-29550", "CVE-2023-1999");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-04-18 10:10:05 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-12 12:45:53 +0530 (Wed, 12 Apr 2023)");
  script_name("Mozilla Firefox Security Updates (mfsa2023-14) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Mozilla Maintenance Service Write-lock bypass

  - Fullscreen notification obscured

  - Double-free in libwebp

  - Potential Memory Corruption following Garbage Collector compaction

  - Invalid free from JavaScript code

  - Content-Disposition filename truncation leads to Reflected File Download

  - Bypass of file download extension restrictions

  - Windows Save As dialog resolved environment variables

  - Memory Corruption in Safe Browsing Code

  - Incorrect optimization result on ARM64

  - Memory safety bugs fixed in Firefox 112 and Firefox ESR 102.10");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, disclose sensitive information and
  conduct spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 102.10 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 102.10
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-14/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"102.10"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.10", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
