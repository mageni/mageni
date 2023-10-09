# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832500");
  script_version("2023-09-15T05:06:15+0000");
  script_cve_id("CVE-2023-41764", "CVE-2023-36767");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-09-15 05:06:15 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-13 17:28:37 +0530 (Wed, 13 Sep 2023)");
  script_name("Microsoft Office 2013 Service Pack 1 Multiple Vulnerabilities (KB5002477)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002477");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Spoofing Vulnerability in Microsoft Office.

  - Security Feature Bypass Vulnerability in Microsoft Office.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct spoofing attacks and secuirity feature bypass on an affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002477");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer|| officeVer !~ "^15\.") {
  exit(0);
}

if(!os_arch = get_kb_item("SMB/Windows/Arch")) {
  exit(0);
}

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
}
else if("x64" >< os_arch) {
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion");
}

foreach key(key_list)
{
  msPath = registry_get_sz(key:key, item:"CommonFilesDir");
  if(msPath)
  {
    offPath = msPath + "\Microsoft Office\Office15";
    msdllVer = fetch_file_version(sysPath:offPath, file_name:"Msores.dll");

    if(msdllVer && msdllVer =~ "^15\.") {
      if(version_is_less(version:msdllVer, test_version:"15.0.5241.1000")) {
        report = report_fixed_ver( file_checked:offPath + "\Msores.dll",
                                   file_version:msdllVer, vulnerable_range:"15.0 - 15.0.5241.0999");
         security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
