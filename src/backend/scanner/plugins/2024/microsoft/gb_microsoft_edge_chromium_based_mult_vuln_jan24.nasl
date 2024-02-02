# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832775");
  script_version("2024-01-24T14:38:46+0000");
  script_cve_id("CVE-2024-0225", "CVE-2024-0224", "CVE-2024-0223", "CVE-2024-0222");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-24 14:38:46 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-08 19:41:00 +0000 (Mon, 08 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-10 17:18:53 +0530 (Wed, 10 Jan 2024)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities - Jan24");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An heap buffer overflow issue in ANGLE.

  - An use after free error in WebGPU, WebAudio and ANGLE.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and conduct heap buffer overflow attacks on an
  affected system.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to  version 120.0.2210.121.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0225");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"120.0.2210.121")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"120.0.2210.121", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);