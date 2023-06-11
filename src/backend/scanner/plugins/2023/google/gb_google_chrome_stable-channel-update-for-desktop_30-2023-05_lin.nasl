# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826995");
  script_version("2023-06-02T09:09:16+0000");
  script_cve_id("CVE-2023-2929", "CVE-2023-2930", "CVE-2023-2931", "CVE-2023-2932",
                "CVE-2023-2933", "CVE-2023-2934", "CVE-2023-2935", "CVE-2023-2936",
                "CVE-2023-2937", "CVE-2023-2938", "CVE-2023-2939", "CVE-2023-2940",
                "CVE-2023-2941");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-06-02 09:09:16 +0000 (Fri, 02 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-01 11:22:12 +0530 (Thu, 01 Jun 2023)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_30-2023-05)-Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out of bounds write in Swiftshader.

  - Use after free in Extensions.

  - Use after free in PDF.

  - Out of bounds memory access in Mojo.

  - Type Confusion in V8.

  - Inappropriate implementation in Picture In Picture.

  - Insufficient data validation in Installer.

  - Inappropriate implementation in Downloads.

  - Inappropriate implementation in Extensions API.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  114.0.5735.90 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  114.0.5735.90 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/05/stable-channel-update-for-desktop_30.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"114.0.5735.90"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"114.0.5735.90", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
