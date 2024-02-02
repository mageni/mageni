# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832577");
  script_version("2023-11-17T16:10:13+0000");
  script_cve_id("CVE-2023-5996");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-15 15:48:00 +0000 (Wed, 15 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-09 16:28:02 +0530 (Thu, 09 Nov 2023)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2023-11) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to an Use-after-free
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an Use after free error in
  WebAudio.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to potentially exploit heap corruption via a crafted HTML page on
  an affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  119.0.6045.123 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  119.0.6045.123 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/11/stable-channel-update-for-desktop.html");
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

if(version_is_less(version:vers, test_version:"119.0.6045.123")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"119.0.6045.123", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
