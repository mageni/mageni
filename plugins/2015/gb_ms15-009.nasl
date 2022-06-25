###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Memory Corruption Vulnerabilities (3034682)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805136");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2014-8967", "CVE-2015-0017", "CVE-2015-0018", "CVE-2015-0019",
                "CVE-2015-0020", "CVE-2015-0021", "CVE-2015-0022", "CVE-2015-0023",
                "CVE-2015-0025", "CVE-2015-0026", "CVE-2015-0027", "CVE-2015-0028",
                "CVE-2015-0029", "CVE-2015-0030", "CVE-2015-0031", "CVE-2015-0035",
                "CVE-2015-0036", "CVE-2015-0037", "CVE-2015-0038", "CVE-2015-0039",
                "CVE-2015-0040", "CVE-2015-0041", "CVE-2015-0042", "CVE-2015-0043",
                "CVE-2015-0044", "CVE-2015-0045", "CVE-2015-0046", "CVE-2015-0048",
                "CVE-2015-0049", "CVE-2015-0050", "CVE-2015-0051", "CVE-2015-0052",
                "CVE-2015-0053", "CVE-2015-0054", "CVE-2015-0055", "CVE-2015-0066",
                "CVE-2015-0067", "CVE-2015-0068", "CVE-2015-0069", "CVE-2015-0070",
                "CVE-2015-0071");
  script_bugtraq_id(71483, 72402, 72403, 72425, 72426, 72436, 72437, 72438,
                    72439, 72440, 72441, 72442, 72443, 72444, 72445, 72447,
                    72446, 72448, 72404, 72409, 72410, 72411, 72412, 72413,
                    72414, 72415, 72416, 72417, 72418, 72419, 72453, 72420,
                    72421, 72478, 72479, 72422, 72423, 72424, 72454, 72480,
                    72455);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2015-02-11 08:41:05 +0530 (Wed, 11 Feb 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Memory Corruption Vulnerabilities (3034682)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-009.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an error related
  to display:run-in handling, user supplied input is not properly validated and
  multiple unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow context

  - dependent attacker to corrupt memory, execute arbitrary code and compromise
  a user's system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version
  6.x/7.x/8.x/9.x/10.x/11.x");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3034682");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-009");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^([6-9|1[01])\."){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mshtml.dll");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"system32\Jscript9.dll");
if(!dllVer && !dllVer2){
  exit(0);
}

if(hotfix_check_sp(win2003:3, win2003x64:3) > 0 && dllVer)
{
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5508") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21431")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23643")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19280")||
       version_in_range(version:dllVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23589")||
       version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19599")||
       version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23654")||
       version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16608")||
       version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20724")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }

  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16619")||
       version_in_range(version:dllVer2, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20729")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"8.0.7601.17000", test_version2:"8.0.7601.18714")||
       version_in_range(version:dllVer, test_version:"8.0.7601.22000", test_version2:"8.0.7601.22920")||
       version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16608")||
       version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20724")||
       version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17228")||
       version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21344")||
       version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.17630")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }

  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16619")||
      version_in_range(version:dllVer2, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20729")||
      version_in_range(version:dllVer2, test_version:"10.0.9200.17000", test_version2:"10.0.9200.17240")||
      version_in_range(version:dllVer2, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21358")||
      version_in_range(version:dllVer2, test_version:"11.0.9600.17000", test_version2:"11.0.9600.17639")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17227")||
       version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.21344")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }

  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"10.0.9200.17000", test_version2:"10.0.9200.17240")||
       version_in_range(version:dllVer2, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21358")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(dllVer && version_is_less(version:dllVer, test_version:"11.0.9600.17631")||
     dllVer2 && version_is_less(version:dllVer2, test_version:"11.0.9600.17640")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
