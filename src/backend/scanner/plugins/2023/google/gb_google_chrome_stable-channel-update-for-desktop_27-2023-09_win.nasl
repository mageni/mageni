# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832534");
  script_version("2023-10-13T05:06:10+0000");
  script_cve_id("CVE-2023-5217", "CVE-2023-5186", "CVE-2023-5187");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-30 04:15:00 +0000 (Sat, 30 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-10-04 16:38:48 +0530 (Wed, 04 Oct 2023)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_27-2023-09) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Heap buffer overflow in vp8 encoding in libvpx.

  - Use after free in Passwords.

  - Use after free in Extensions.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause the buffer to overflow and execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"Google Chrome versions prior to
  117.0.5938.132 on Windows");

  script_tag(name:"solution", value:"Upgrade to version 117.0.5938.132 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_27.html");
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

if(version_is_less(version:vers, test_version:"117.0.5938.132")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"117.0.5938.132", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
