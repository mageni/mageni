# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832264");
  script_version("2023-09-26T05:05:30+0000");
  script_cve_id("CVE-2021-21227", "CVE-2021-21232", "CVE-2021-21233", "CVE-2021-21228",
                "CVE-2021-4324", "CVE-2021-21229", "CVE-2021-21230", "CVE-2021-21231");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-09-26 05:05:30 +0000 (Tue, 26 Sep 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-01 13:35:00 +0000 (Tue, 01 Jun 2021)");
  script_tag(name:"creation_date", value:"2023-09-07 17:07:13 +0530 (Thu, 07 Sep 2023)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_26-2021-04) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Insufficient data validation in V8.

  - Use after free in Dev Tools.

  - Heap buffer overflow in ANGLE.

  - Insufficient policy enforcement in extensions.

  - Incorrect security UI in downloads.

  - Type Confusion in V8.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  90.0.4430.93 on Windows");

  script_tag(name:"solution", value:"Upgrade to version
  90.0.4430.93 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/04/stable-channel-update-for-desktop_26.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"90.0.4430.93")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"90.0.4430.93", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
