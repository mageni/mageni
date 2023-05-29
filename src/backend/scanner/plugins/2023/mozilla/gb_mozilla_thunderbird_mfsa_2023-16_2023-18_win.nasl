# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832070");
  script_version("2023-05-12T10:50:26+0000");
  script_cve_id("CVE-2023-32205", "CVE-2023-32206", "CVE-2023-32207", "CVE-2023-32211",
                "CVE-2023-32212", "CVE-2023-32213", "CVE-2023-32214", "CVE-2023-32215");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-05-12 10:50:26 +0000 (Fri, 12 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-11 12:10:03 +0530 (Thu, 11 May 2023)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2023-16_2023-18)-Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Crash in RLBox Expat driver.

  - Permissions request bypass via clickjacking.

  - Content process crash due to invalid wasm code.

  - Potential spoof due to obscured address bar.

  - Potential memory corruption in FileReader::DoReadData().

  - Potential DoS via exposed protocol handlers.

  - Browser prompts obscured due to popups.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  disclose sensitive information, execute arbitrary code and cause denial of service
  condition.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 102.11 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 102.11
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-18/");
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
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"102.11"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.11", install_path:path);
  security_message(data:report);
  exit(0);
}
