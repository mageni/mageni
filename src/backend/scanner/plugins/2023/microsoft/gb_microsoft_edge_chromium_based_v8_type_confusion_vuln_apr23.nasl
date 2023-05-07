# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832050");
  script_version("2023-05-04T09:51:03+0000");
  script_cve_id("CVE-2023-2033");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"creation_date", value:"2023-04-20 15:10:42 +0530 (Thu, 20 Apr 2023)");
  script_name("Microsoft Edge (Chromium-Based) Type Confusion Vulnerability (April 2023)");

  script_tag(name:"summary", value:"Microsoft Edge (Chromium-Based) is prone to a type
  confusion vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a Type confusion in V8 engine
  in Google Chrome.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers exploit heap corruption via a crafted HTML page and execute
  arbitrary code and install malware");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 112.0.1722.48.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2033");
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

if(version_is_less(version:vers, test_version:"112.0.1722.48"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"112.0.1722.48", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
