# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832068");
  script_version("2023-05-11T09:09:33+0000");
  script_cve_id("CVE-2023-29354", "CVE-2023-29350", "CVE-2023-2468", "CVE-2023-2467",
                "CVE-2023-2466", "CVE-2023-2465", "CVE-2023-2464", "CVE-2023-2463",
                "CVE-2023-2462", "CVE-2023-2460", "CVE-2023-2459");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-05-11 09:09:33 +0000 (Thu, 11 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-10 10:41:27 +0530 (Wed, 10 May 2023)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities - May23");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An inappropriate implementation in PictureInPicture.

  - An inappropriate implementation in Prompts.

  - An insufficient validation of untrusted input in Extensions.

  - An inappropriate implementation in CORS");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to  execute arbitrary code, gain access to sensitive information, bypass
  security restrictions, cause denial of service and may have other impacts on
  affected systems.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 113.0.1774.35.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29350");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_chromium_based_detect_win.nasl");
  script_mandatory_keys("microsoft_edge_chromium/installed", "microsoft_edge_chromium/ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"113.0.1774.35"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"113.0.1774.35", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
