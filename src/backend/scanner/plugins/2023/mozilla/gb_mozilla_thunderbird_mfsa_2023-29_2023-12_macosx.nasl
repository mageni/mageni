# copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832517");
  script_version("2023-10-06T16:09:51+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-4863");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-14 17:27:16 +0530 (Thu, 14 Sep 2023)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2023-29_2023-12)- MAC OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to a heap buffer
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to heap buffer
  overflow in WebP");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to cause the buffer to overflow, potentially overwriting
  adjacent memory and corrupting data on an affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  102.15.1 and 115.x prior to 115.2.2 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 102.15.1 or 115.2.2
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-40/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
 exit( 0 );

tbVer = infos["version"];
tbPath = infos["location"];

if(version_is_less(version:tbVer, test_version:"102.15.1")) {
  fix = "102.15.1";
}
else if(tbVer =~ "^115\." && version_is_less(version:tbVer, test_version:"115.2.2")) {
  fix = "115.2.2";
}

if(fix) {
  report = report_fixed_ver(installed_version:tbVer, fixed_version:fix, install_path:tbPath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
