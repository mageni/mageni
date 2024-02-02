# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832802");
  script_version("2024-01-30T14:37:03+0000");
  script_cve_id("CVE-2024-0807", "CVE-2024-0812", "CVE-2024-0808", "CVE-2024-0810",
                "CVE-2024-0814", "CVE-2024-0813", "CVE-2024-0806", "CVE-2024-0805",
                "CVE-2024-0804", "CVE-2024-0811", "CVE-2024-0809");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-30 14:37:03 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 14:25:00 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-24 16:10:44 +0530 (Wed, 24 Jan 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_23-2024-01) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free errors in WebAudio, Reading Mode and Passwords.

  - Inappropriate implementation in Accessibility.

  - Integer underflow in WebUI.

  - Insufficient policy enforcement in DevTools and iOS Security UI.

  - Incorrect security UI in Payments.

  - Inappropriate implementation in Downloads, Extensions API and Autofill.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct
  spoofing and cause a heap corruption on an affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  121.0.6167.85 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 121.0.6167.85 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/01/stable-channel-update-for-desktop_23.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"121.0.6167.85")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"121.0.6167.85", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
