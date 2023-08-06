# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832234");
  script_version("2023-08-04T16:09:15+0000");
  script_cve_id("CVE-2023-4068", "CVE-2023-4069", "CVE-2023-4070", "CVE-2023-4071",
                "CVE-2023-4072", "CVE-2023-4073", "CVE-2023-4074", "CVE-2023-4075",
                "CVE-2023-4076", "CVE-2023-4077", "CVE-2023-4078");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-08-04 16:09:15 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-03 12:17:40 +0530 (Thu, 03 Aug 2023)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2023-08) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Type Confusion in V8.

  - Heap buffer overflow in Visuals.

  - Out of bounds read and write in WebGL.

  - Out of bounds memory access in ANGLE.

  - Use after free in Blink Task Scheduling.

  - Use after free in Cast.

  - Use after free in WebRTC.

  - Insufficient data validation in Extensions.

  - Inappropriate implementation in Extensions.");

  script_tag(name:"impact", value:"Successful exploitation would allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  115.0.5790.170 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 115.0.5790.170 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/08/stable-channel-update-for-desktop.html");
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

if(version_is_less(version:vers, test_version:"115.0.5790.170")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.0.5790.170", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
