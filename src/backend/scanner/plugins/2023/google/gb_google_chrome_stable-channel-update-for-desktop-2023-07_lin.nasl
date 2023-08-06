# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832324");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2023-3727", "CVE-2023-3728", "CVE-2023-3730", "CVE-2023-3732",
                "CVE-2023-3733", "CVE-2023-3734", "CVE-2023-3735", "CVE-2023-3736",
                "CVE-2023-3737", "CVE-2023-3738", "CVE-2023-3740");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-19 21:00:44 +0530 (Wed, 19 Jul 2023)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2023-07) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free in WebRTC.

  - Use after free in Tab Groups.

  - Out of bounds memory access in Mojo.

  - Inappropriate implementation in WebApp Installs.

  - Inappropriate implementation in Picture In Picture.

  - Inappropriate implementation in Web API Permission Prompts.

  - Inappropriate implementation in Custom Tabs.

  - Inappropriate implementation in Notifications.

  - Inappropriate implementation in Autofill.

  - Insufficient validation of untrusted input in Themes.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  115.0.5790.98 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 115.0.5790.98 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/07/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.0.5790.98")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.0.5790.98", install_path:path);

  security_message(port:0, data:report);
  exit(0);
}

exit(99);
