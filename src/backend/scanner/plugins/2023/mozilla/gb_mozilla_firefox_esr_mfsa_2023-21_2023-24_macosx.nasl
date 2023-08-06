# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832097");
  script_version("2023-07-10T08:07:43+0000");
  script_cve_id("CVE-2023-37201", "CVE-2023-37202", "CVE-2023-37207", "CVE-2023-37208",
                "CVE-2023-37211");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-05 15:16:30 +0530 (Wed, 05 Jul 2023)");
  script_name("Mozilla Firefox ESR Security Updates (mfsa_2023-21_2023-24) - MAC OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use-after-free in WebRTC certificate generation.

  - Potential use-after-free from compartment mismatch in SpiderMonkey.

  - Fullscreen notification obscured.

  - Lack of warning when opening Diagcab files.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on an affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  102.13 on MAC OS X.");

  script_tag(name:"solution", value:"Update to version 102.13
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-23/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"102.13")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.13", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
