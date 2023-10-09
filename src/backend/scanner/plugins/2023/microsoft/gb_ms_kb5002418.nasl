# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832163");
  script_version("2023-08-24T05:06:01+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-36884");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-09 13:10:14 +0530 (Wed, 09 Aug 2023)");
  script_name("Microsoft Visio 2016 Defense in Depth Security Update (KB5002418)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002418.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"This is the Windows Search Remote Code
  Execution Vulnerability (CVE-2023-36884).");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Visio 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002418");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/en-US/vulnerability/ADV230003");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\visio.exe", item:"Path");
if(!sysPath)
  exit(0);

version = fetch_file_version(sysPath:sysPath, file_name:"visio.exe");
if(!version)
  exit(0);

if(version_in_range(version:version, test_version:"16.0", test_version2:"16.0.5408.1001")) {
  report = report_fixed_ver(file_checked:"visio.exe", file_version:version, vulnerable_range:"16.0 - 16.0.5408.1001");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
