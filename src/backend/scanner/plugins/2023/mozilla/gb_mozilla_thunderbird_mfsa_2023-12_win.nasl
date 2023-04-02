# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832100");
  script_version("2023-03-31T10:08:38+0000");
  script_cve_id("CVE-2023-28427");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-03-31 10:08:38 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-31 12:48:32 +0530 (Fri, 31 Mar 2023)");
  script_name("Mozilla Thunderbird Security Update(mfsa_2023-12)-Windows");

  script_tag(name:"summary", value:"Thunderbird vulnerable to denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the handling
  of Matrix SDK bundled with Thunderbird.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  execute arbitrary code and cause denial of service condition.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 102.9.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 102.9.1
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-12/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"102.9.1"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"102.9.1", install_path:tbPath);
  security_message(data:report);
  exit(0);
}
