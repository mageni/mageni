# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832339");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2023-38572", "CVE-2023-38594", "CVE-2023-38595", "CVE-2023-38600",
                "CVE-2023-38611", "CVE-2023-38597", "CVE-2023-38133");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-25 15:52:56 +0530 (Tue, 25 Jul 2023)");
  script_name("Apple Safari Security Updates (HT213847)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error in same origin policy.

  - An error in processing web content.

  - An improper state and memory management.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow attackers to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Apple Safari versions before 16.6");

  script_tag(name:"solution", value:"Upgrade to version 16.6 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213847");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"16.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"16.6", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
