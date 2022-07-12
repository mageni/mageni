##############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Remote Code Execution Vulnerabilities (955047)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900046");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
  script_bugtraq_id(31067);
  script_cve_id("CVE-2008-3007");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (955047)");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-055.mspx");

  script_tag(name:"summary", value:"This host is missing critical security update according to
  Microsoft Bulletin MS08-055.");

  script_tag(name:"insight", value:"The issue is due to an error in the parsing of a URI using
  the onenote:// protocol handler.");

  script_tag(name:"affected", value:"Microsoft Office XP/2003/2007 on Windows (All).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"impact", value:"Remote attackers could be able to execute arbitrary code
  via a specially crafted OneNote URI referencing a specially crafted One Note file.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0){
  exit(0);
}

prgmDir = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(!prgmDir){
  exit(0);
}

offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

if(offVer =~ "^10\.") {

  dllPath = prgmDir + "\Common Files\Microsoft Shared\Office10\MSO.DLL";

  vers = get_version(dllPath:dllPath);
  if(!vers){
    exit(0);
  }

  # version < 10.0.6845
  if(egrep(pattern:"^10\.0\.([0-5]?[0-9]?[0-9]?[0-9]|6([0-7][0-9][0-9]|8([0-3][0-9]|4[0-4])))$", string:vers)){
    report = report_fixed_ver(installed_version:vers, fixed_version:"10.0.6845", file_checked:dllPath);
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}

if(offVer =~ "^11\.") {

  dllPath = prgmDir + "\Common Files\Microsoft Shared\Office11\MSO.DLL";

  vers = get_version(dllPath:dllPath);
  if(!vers){
    exit(0);
  }

  # version < 11.0.8221
  if(egrep(pattern:"^11\.0\.([0-7]?[0-9]?[0-9]?[0-9]|8([01][0-9][0-9]|2[01][0-9]|220))$", string:vers)){
    report = report_fixed_ver(installed_version:vers, fixed_version:"11.0.8221", file_checked:dllPath);
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}

if(offVer =~ "^12\.") {

  dllPath = prgmDir + "\Common Files\Microsoft Shared\Office12\MSO.DLL";

  vers = get_version(dllPath:dllPath);
  if(!vers){
    exit(0);
  }

  # version < 12.0.6320.5000
  if(egrep(pattern:"^12\.0\.([0-5].*|62.*|63[01][0-9].*|6320\.[0-4]?[0-9]?[0-9]?[0-9])$", string:vers)){
    report = report_fixed_ver(installed_version:vers, fixed_version:"12.0.6320.5000", file_checked:dllPath);
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);