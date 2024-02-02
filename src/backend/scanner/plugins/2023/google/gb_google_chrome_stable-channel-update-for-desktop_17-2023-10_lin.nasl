# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832568");
  script_version("2023-11-01T05:05:34+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-11-01 05:05:34 +0000 (Wed, 01 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-27 19:07:55 +0530 (Fri, 27 Oct 2023)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_17-2023-10) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to an unspecified
  vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to cause unspecified impact.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  118.0.5993.88 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  118.0.5993.88 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/10/stable-channel-update-for-desktop_17.html");
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

if(version_is_less(version:vers, test_version:"118.0.5993.88")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"118.0.5993.88", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
