# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821392");
  script_version("2023-06-27T05:05:30+0000");
  script_cve_id("CVE-2023-1213", "CVE-2023-1214", "CVE-2023-1215", "CVE-2023-1216",
                "CVE-2023-1217", "CVE-2023-1218", "CVE-2023-1219", "CVE-2023-1220",
                "CVE-2023-1221", "CVE-2023-1222", "CVE-2023-1223", "CVE-2023-1224",
                "CVE-2023-1225", "CVE-2023-1226", "CVE-2023-1227", "CVE-2023-1228",
                "CVE-2023-1229", "CVE-2023-1230", "CVE-2023-1231", "CVE-2023-1232",
                "CVE-2023-1233", "CVE-2023-1234", "CVE-2023-1235", "CVE-2023-1236");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-03-09 12:31:05 +0530 (Thu, 09 Mar 2023)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2023-03)-Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free in Swiftshader.

  - Type Confusion in V8.

  - Type Confusion in CSS.

  - Use after free in DevTools.

  - Stack buffer overflow in Crash reporting.

  - Use after free in WebRTC.

  - Heap buffer overflow in Metrics.

  - Heap buffer overflow in UMA.

  - Insufficient policy enforcement in Extensions API.

  - Heap buffer overflow in Web Audio API.

  - Insufficient policy enforcement in Autofill.

  - Insufficient policy enforcement in Web Payments API.

  - Insufficient policy enforcement in Navigation.

  - Use after free in Core.

  - Insufficient policy enforcement in Intents.

  - Inappropriate implementation in Permission prompts.

  - Inappropriate implementation in WebApp Installs.

  - Inappropriate implementation in Autofill.

  - Insufficient policy enforcement in Resource Timing.

  - Inappropriate implementation in Intents.

  - Type Confusion in DevTools.

  - Inappropriate implementation in Internals.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code, bypass security restrictions, conduct spoofing and
  cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 111.0.5563.64 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  111.0.5563.64 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/03/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"111.0.5563.64"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"111.0.5563.64", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
