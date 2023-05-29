# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826988");
  script_version("2023-05-22T12:17:59+0000");
  script_cve_id("CVE-2023-32402", "CVE-2023-32409", "CVE-2023-32423", "CVE-2023-28204",
                "CVE-2023-32373");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-05-22 12:17:59 +0000 (Mon, 22 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-22 11:55:29 +0530 (Mon, 22 May 2023)");
  script_name("Apple Safari Security Update (HT213762)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple
  vulnerabilities according to Apple security advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple out-of-bounds read was addressed with improved input validation.

  - A buffer overflow issue was addressed with improved memory handling.

  - A use-after-free issue was addressed with improved memory management.

  - Improper bounds checks.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow attackers to conduct arbitrary code execution and disclose sensitive
  information.");

  script_tag(name:"affected", value:"Apple Safari versions before 16.5");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 16.5 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213762");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}
include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
safVer = infos['version'];
safPath = infos['location'];

if(version_is_less(version:safVer, test_version:"16.5"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"16.5", install_path:safPath);
  security_message(data:report);
  exit(0);
}
exit(0);
