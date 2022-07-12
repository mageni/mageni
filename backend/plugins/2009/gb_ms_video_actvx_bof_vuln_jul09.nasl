###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Video ActiveX Control 'msvidctl.dll' BOF Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800829");
  script_version("2019-05-03T12:31:27+0000");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0015", "CVE-2008-0020");
  script_bugtraq_id(35558);
  script_name("Microsoft Video ActiveX Control 'msvidctl.dll' BOF Vulnerability");

  script_xref(name:"URL", value:"http://www.iss.net/threats/329.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35683");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/972890");
  script_xref(name:"URL", value:"http://isc.sans.org/diary.html?storyid=6733");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS09-032.mspx");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/972890.mspx");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code that affects
  the TV Tuner library, and can cause memory corruption.");

  script_tag(name:"affected", value:"Microsoft Video ActiveX Control on Windows 2000/XP/2003");

  script_tag(name:"insight", value:"- Stack-based buffer overflow error in MPEG2TuneRequest in msvidctl.dll in
    Microsoft DirectShow can be exploited via a crafted web page.

  - Unspecified error in msvidctl.dll is caused via unknown vectors that trigger
    memory corruption.");

  script_tag(name:"summary", value:"This host is installed with Microsoft Video ActiveX Control and is prone to
  Buffer Overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.

  Workaround: Set the killbit for the CLSID {0955AC62-BF2E-4CBA-A2B9-A63F772D46CF}");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# MS09-032 Hotfix (973346)
if(hotfix_missing(name:"973346") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  vers = fetch_file_version(sysPath:sysPath, file_name:"msvidctl.dll");
  if(!vers){
    exit(0);
  }
}

if(egrep(pattern:"^6\..*", string:vers))
{
  if(is_killbit_set(clsid:"{0955AC62-BF2E-4CBA-A2B9-A63F772D46CF}") == 0){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}
dllVer = fetch_file_version(sysPath:sysPath, file_name:"msvidctl.dll");
if(!dllVer){
  exit(0);
}

if(egrep(pattern:"^6\..*", string:dllVer))
{
  if(is_killbit_set(clsid:"{0955AC62-BF2E-4CBA-A2B9-A63F772D46CF}") == 0){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
