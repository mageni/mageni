# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832507");
  script_version("2023-10-06T16:09:51+0000");
  script_cve_id("CVE-2023-36764");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-13 13:43:33 +0530 (Wed, 13 Sep 2023)");
  script_name("Microsoft SharePoint Server 2019 Elevation of Privilege Vulnerability (KB5002472)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5002472");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an elevation of privilege vulnerability in Microsoft SharePoint Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain elevated privileges on an affected system.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2019.");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002472");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

CPE = "cpe:/a:microsoft:sharepoint_server";

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
if(vers !~ "^16\.")
  exit(0);

if(!os_arch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
}
else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                       "SOFTWARE\Microsoft\Windows\CurrentVersion");
}

foreach key(key_list)
{
  path = registry_get_sz(key:key, item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\Web Server Extensions\16\BIN";
    dllVer = fetch_file_version(sysPath:path, file_name:"Onetutil.dll");

    ## SharePoint Server 2019 starts with 16.0.10337.12109
    if(dllVer =~ "^16\.0\." && version_in_range(version:dllVer, test_version:"16.0.10337.12109", test_version2:"16.0.10395.20015")) {
      report = report_fixed_ver(file_checked:path + "\Onetutil.dll",
                                file_version:dllVer, vulnerable_range:"16.0.10337.12109 - 16.0.10402.20015");
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

exit(99);
