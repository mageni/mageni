# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832736");
  script_version("2023-12-14T08:20:35+0000");
  script_cve_id("CVE-2023-38174", "CVE-2023-35618", "CVE-2023-36880");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-14 08:20:35 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-07 21:15:00 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 15:51:36 +0530 (Wed, 13 Dec 2023)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities - Dec23");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability.

  - Microsoft Edge (Chromium-based) multiple Information Disclosure
    vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, gain access to sensitive information and conduct
  elevation of privilege on an affected system.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 120.0.2210.61.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35618");
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

if(version_is_less(version:vers, test_version:"120.0.2210.61")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"120.0.2210.61", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
