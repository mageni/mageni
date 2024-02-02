# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832572");
  script_version("2023-11-10T16:09:31+0000");
  script_cve_id("CVE-2023-5480", "CVE-2023-5482", "CVE-2023-5849", "CVE-2023-5850",
                "CVE-2023-5851", "CVE-2023-5852", "CVE-2023-5853", "CVE-2023-5854",
                "CVE-2023-5855", "CVE-2023-5856", "CVE-2023-5857", "CVE-2023-5858",
                "CVE-2023-5859");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-10 16:09:31 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 19:49:00 +0000 (Wed, 08 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-03 12:02:18 +0530 (Fri, 03 Nov 2023)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_31-2023-10) - MAC OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Inappropriate implementation in Payments.

  - Insufficient data validation in USB.

  - Integer overflow in USB.

  - Incorrect security UI in Downloads.

  - Inappropriate implementation in Downloads.

  - Use after free in Printing.

  - Use after free in Profiles.

  - Use after free in Reading Mode.

  - Use after free in Side Panel.

  - Inappropriate implementation in WebApp Provider.

  - Incorrect security UI in Picture In Picture.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on an affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  119.0.6045.105 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  119.0.6045.105 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/10/stable-channel-update-for-desktop_31.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"119.0.6045.105")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"119.0.6045.105", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
