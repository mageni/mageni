# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832633");
  script_version("2023-11-24T16:09:32+0000");
  script_cve_id("CVE-2023-36014", "CVE-2023-36024", "CVE-2023-36027");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:P");
  script_tag(name:"last_modification", value:"2023-11-24 16:09:32 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-15 17:47:00 +0000 (Wed, 15 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-24 13:51:53 +0530 (Fri, 24 Nov 2023)");
  script_name("Microsoft Edge (Chromium-Based) Remote Code Execution And Elevation of Privilege Vulnerabilities - November23");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability.

  - Multiple Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution and elevate privileges on an affected system.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 119.0.2151.58.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36008");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_chromium_based_detect_win.nasl");
  script_mandatory_keys("microsoft_edge_chromium/installed", "microsoft_edge_chromium/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
 exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"119.0.2151.58")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"119.0.2151.58", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
