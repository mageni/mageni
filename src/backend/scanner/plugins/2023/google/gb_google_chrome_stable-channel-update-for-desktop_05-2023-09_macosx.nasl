# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832268");
  script_version("2023-09-12T05:05:19+0000");
  script_cve_id("CVE-2023-4761", "CVE-2023-4762", "CVE-2023-4763", "CVE-2023-4764");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-09-12 05:05:19 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-07 17:36:38 +0530 (Thu, 07 Sep 2023)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_05-2023-09) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out of bounds memory access in FedCM.

  - Type Confusion in V8.

  - Use after free in Networks.

  - Incorrect security UI in BFCache.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code, conduct spoofing and cause denial of service on an affected
  system.");

  script_tag(name:"affected", value:"Google Chrome versions prior to
  116.0.5845.179 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to version 116.0.5845.179/180 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop.html");
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

if(version_is_less(version:vers, test_version:"116.0.5845.179")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"116.0.5845.179", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
