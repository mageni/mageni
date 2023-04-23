# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832042");
  script_version("2023-04-20T12:00:18+0000");
  script_cve_id("CVE-2023-24935", "CVE-2023-1823", "CVE-2023-1822", "CVE-2023-1821",
                "CVE-2023-1820", "CVE-2023-1819", "CVE-2023-1818", "CVE-2023-1817",
                "CVE-2023-1816", "CVE-2023-1815", "CVE-2023-1814", "CVE-2023-1813",
                "CVE-2023-1812", "CVE-2023-1811", "CVE-2023-1810");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-04-20 12:00:18 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-12 17:21:33 +0530 (Wed, 12 Apr 2023)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities - Apr23");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An use after free error in Networking APIs.

  - An out of bounds memory access in DOM Bindings.

  - Multiple heap buffer overflow errors in Visuals.

  - An use after free error in Frames.

  - An use after free error in Vulkan.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to  execute arbitrary code, gain access to sensitive information, bypass
  security restrictions, cause denial of service and may have other impacts.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 112.0.5615.34.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1815");
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

if(version_is_less(version:vers, test_version:"112.0.5615.34"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"112.0.5615.34", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
