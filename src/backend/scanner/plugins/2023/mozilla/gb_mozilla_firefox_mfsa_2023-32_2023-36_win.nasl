# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832260");
  script_version("2023-09-01T05:05:17+0000");
  script_cve_id("CVE-2023-4573", "CVE-2023-4574", "CVE-2023-4575", "CVE-2023-4576",
                "CVE-2023-4577", "CVE-2023-4578", "CVE-2023-4579", "CVE-2023-4580",
                "CVE-2023-4581", "CVE-2023-4585", "CVE-2023-4583", "CVE-2023-4584");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-09-01 05:05:17 +0000 (Fri, 01 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-08-30 19:31:29 +0530 (Wed, 30 Aug 2023)");
  script_name("Mozilla Firefox Security Update (mfsa_2023-32_2023-36) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Memory corruption in IPC CanvasTranslator.

  - Memory corruption in IPC ColorPickerShownCallback.

  - Memory corruption in IPC FilePickerShownCallback.

  - Integer Overflow in RecordedSourceSurfaceCreation.

  - Memory corruption in JIT UpdateRegExpStatics.

  - Error reporting methods in SpiderMonkey could have triggered an Out of Memory Exception.

  - Persisted search terms were formatted as URLs.

  - Push notifications saved to disk unencrypted.

  - XLL file extensions were downloadable without warnings.

  - Browsing Context potentially not cleared when closing Private Window.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service and disclose
  sensitive information on affected systems.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  117 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 117 or later,
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-34/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"117")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"117", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}
