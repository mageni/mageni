# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832180");
  script_version("2023-09-15T05:06:15+0000");
  script_cve_id("CVE-2023-36801", "CVE-2023-36803", "CVE-2023-36804", "CVE-2023-36805",
                "CVE-2023-38139", "CVE-2023-38140", "CVE-2023-38141", "CVE-2023-38142",
                "CVE-2023-38143", "CVE-2023-38144", "CVE-2023-38147", "CVE-2023-38149",
                "CVE-2023-38152", "CVE-2023-38160", "CVE-2023-38161", "CVE-2023-38162");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-09-15 05:06:15 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-13 13:33:15 +0530 (Wed, 13 Sep 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5030213)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5030213");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An issue that affects the Microsoft Distributed Transaction Coordinator (DTC).
     it has a handle leak. Because of this, the system runs out of memory.

  - An issue that affects the Resultant Set of Policy (RSOP).

  - An issue that affects Server Message Block (SMB).

  - An issue that affects scheduled tasks. The tasks fail when they use stored local
    user account credentials.

  - An issue that affects those who use Windows Update for Business. After you are
    asked to change your password at sign in, the change operation fails.

  - An issue that is related to changes in the forwarding of events.

  - An issue that affects the Group Policy Service.

  - An issue that affects the Remote Desktop (RD) Web Role. If you enable that role,
    it fails when you upgrade RD deployments more than once.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information, bypass security restrictions.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 for 32-bit Systems

  - Microsoft Windows 10 Version 1607 for x64-based Systems

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5030213");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}
include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0) {
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.6251")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.14393.0 - 10.0.14393.6251");

  security_message(port:0, data:report);
  exit(0);
}
