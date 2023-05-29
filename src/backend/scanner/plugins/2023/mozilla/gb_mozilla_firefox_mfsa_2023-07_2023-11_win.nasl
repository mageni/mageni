# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832074");
  script_version("2023-05-12T10:50:26+0000");
  script_cve_id("CVE-2023-25750", "CVE-2023-25751", "CVE-2023-28160", "CVE-2023-28164",
                "CVE-2023-28161", "CVE-2023-28162", "CVE-2023-25752", "CVE-2023-28163",
                "CVE-2023-28176", "CVE-2023-28177");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-05-12 10:50:26 +0000 (Fri, 12 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-11 13:35:13 +0530 (Thu, 11 May 2023)");
  script_name("Mozilla Firefox Security Updates(mfsa_2023-07_2023-11)-Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - User Interface lockup with messages combining S/MIME and OpenPGP.

  - Content security policy leak in violation reports using iframes.

  - Screen hijack via browser fullscreen mode.

  - Arbitrary memory write via PKCS 12 in NSS.

  - Potential use-after-free from compartment mismatch in SpiderMonkey.

  - Invalid downcast in SVGUtils::SetupStrokeGeometry.

  - Printing on Windows could potentially crash Thunderbird with some device drivers.

  - Extensions could have opened external schemes without user knowledge.

  - Out of bounds memory write from EncodeInputStream.

  - Opening local .url files could cause unexpected network loads.

  - Web Crypto ImportKey crashes tab.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  disclose sensitive information, execute arbitrary code and cause denial of service
  condition.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 111 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 111
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-09/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"111"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"111", install_path:path);
  security_message(data:report);
  exit(0);
}
