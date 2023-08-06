# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832348");
  script_version("2023-08-04T16:09:15+0000");
  script_cve_id("CVE-2023-4045", "CVE-2023-4046", "CVE-2023-4047", "CVE-2023-4048",
                "CVE-2023-4049", "CVE-2023-4050", "CVE-2023-4052", "CVE-2023-4054",
                "CVE-2023-4055", "CVE-2023-4056", "CVE-2023-4057");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-04 16:09:15 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-03 16:46:44 +0530 (Thu, 03 Aug 2023)");
  script_name("Mozilla Firefox ESR Security Updates (mfsa_2023-26_2023-31) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Offscreen Canvas could have bypassed cross-origin restrictions.

  - Stack buffer overflow in StorageManager.

  - Lack of warning when opening appref-ms files.

  - Cookie jar overflow caused unexpected cookie jar state.

  - Fix potential race conditions when releasing platform objects.

  - Crash in DOMParser due to out-of-memory conditions.

  - Potential permissions request bypass via clickjacking.

  - Incorrect value used during WASM compilation.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  115.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 115.1
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-31/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.1", install_path:path);

  security_message(port:0, data:report);
  exit(0);
}

exit(99);
