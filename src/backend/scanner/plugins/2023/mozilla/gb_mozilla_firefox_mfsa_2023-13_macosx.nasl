# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832111");
  script_version("2023-04-18T10:10:05+0000");
  script_cve_id("CVE-2023-29531", "CVE-2023-29533", "CVE-2023-29535", "CVE-2023-29536",
                "CVE-2023-29537", "CVE-2023-29538", "CVE-2023-29539", "CVE-2023-29540",
                "CVE-2023-29543", "CVE-2023-29544", "CVE-2023-29547", "CVE-2023-29548",
                "CVE-2023-29549", "CVE-2023-29550", "CVE-2023-29551", "CVE-2023-1999");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-04-18 10:10:05 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-12 13:30:07 +0530 (Wed, 12 Apr 2023)");
  script_name("Mozilla Firefox Security Updates (mfsa2023-13) - MAC OS X");

  script_tag(name:"summary", value:"Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out-of-bound memory access in WebGL on macOS

  - Mozilla Maintenance Service Write-lock bypass

  - Fullscreen notification obscured

  - Double-free in libwebp

  - Potential Memory Corruption following Garbage Collector compaction

  - Invalid free from JavaScript code

  - Data Races in font initialization code

  - Directory information could have been leaked to WebExtensions

  - Content-Disposition filename truncation leads to Reflected File Download

  - Iframe sandbox bypass using redirects and sourceMappingUrls

  - Bypass of file download extension restrictions

  - Use-after-free in debugging APIs

  - Memory Corruption in garbage collector

  - Windows Save As dialog resolved environment variables

  - Secure document cookie could be spoofed with insecure cookie

  - Incorrect optimization result on ARM64

  - Javascript's bind function may have failed");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, disclose sensitive information and
  conduct spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  112 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 112
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-13/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"112"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"112", install_path:path);
  security_message(data:report);
  exit(0);
}
