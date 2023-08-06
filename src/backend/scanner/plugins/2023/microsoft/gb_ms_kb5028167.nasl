# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832310");
  script_version("2023-07-14T05:06:08+0000");
  script_cve_id("CVE-2023-35308");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 13:27:16 +0530 (Wed, 12 Jul 2023)");
  script_name("Microsoft Internet Explorer Security Feature Bypass Vulnerability (KB5028167)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5028167");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a Security Feature Bypass vulnerability
  in Windows MSHTML Platform");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary commands on an affected system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 9.x and 11.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5028167");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008:3, win2008x64:3, win2008r2:3, win2012:1, win2012R2:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^[9|11]\."){
  exit(0);
}

iePath = smb_get_system32root();
if(!iePath ){
  exit(0);
}

iedllVer = fetch_file_version(sysPath:iePath, file_name:"Mshtml.dll");
if(!iedllVer){
  exit(0);
}

if(ieVer =~ "^9\." && hotfix_check_sp(win2008:3, win2008x64:3) > 0) {
  if(version_is_less(version:iedllVer, test_version:"9.0.8112.21649")) {
    Vulnerable_range = "Less than 9.0.8112.21649";
  }
}

else if(ieVer =~ "^11\." && hotfix_check_sp(win2012:1, win2008r2:3) > 0) {
  if(version_is_less(version:iedllVer, test_version:"11.0.9600.21068")) {
     Vulnerable_range = "Less than 11.0.9600.21068";
  }
}

else if(ieVer =~ "^11\." && hotfix_check_sp(win2012r2:1) > 0) {
  if(version_is_less(version:iedllVer, test_version:"11.0.9600.20512")) {
     Vulnerable_range = "Less than 11.0.9600.20512";
  }
}

if(Vulnerable_range){
  report = report_fixed_ver(file_checked:iePath + "\Mshtml.dll", file_version:iedllVer, vulnerable_range:Vulnerable_range);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);