# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832371");
  script_version("2023-08-11T05:05:41+0000");
  script_cve_id("CVE-2023-4078", "CVE-2023-4077", "CVE-2023-4076", "CVE-2023-4075",
                "CVE-2023-4074", "CVE-2023-4073", "CVE-2023-4072", "CVE-2023-4071",
                "CVE-2023-4070", "CVE-2023-4069", "CVE-2023-4068", "CVE-2023-38157");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-09 10:40:13 +0530 (Wed, 09 Aug 2023)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities - Aug23");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An inappropriate implementation in extensions.

  - An insufficient data validation in extensions.

  - A use after free in WebRTC.

  - A use after free in cast.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to  execute arbitrary code, gain access to sensitive information, bypass
  security restrictions, cause denial of service and may have other impacts.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 113.0.1774.35.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4078");
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

if(version_is_less(version:vers, test_version:"115.0.1901.200")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.0.1901.200", install_path:path);

  security_message(port:0, data:report);
  exit(0);
}

exit(99);
