##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gdiplus_int_overflow_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Microsoft GDIPlus Library File Integer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.800267");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-04-07 07:29:53 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1217");
  script_bugtraq_id(34250);
  script_name("Microsoft GDIPlus Library File Integer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49438");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0832");
  script_xref(name:"URL", value:"http://bl4cksecurity.blogspot.com/2009/03/microsoft-gdiplus-emf-gpfontsetdata.html");
  script_xref(name:"URL", value:"http://blogs.technet.com/srd/archive/2009/03/26/new-emf-gdiplus-dll-crash-not-exploitable-for-code-execution.aspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause application execution
  termination and also denial of service via a crafted EMF File.");
  script_tag(name:"affected", value:"Microsoft Windows XP Service Pack 2/3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.");
  script_tag(name:"insight", value:"The flaw is in 'GpFont::SetData' Function which has an off-by-one error in the
  gdiplus.dll file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is having GDIPlus Library and is prone to Integer Overflow
  Vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/en-in/default.aspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

getPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"MediaPath");
if(!getPath){
  exit(0);
}

appendPath = getPath - "Media" + "WinSxS\x86_Microsoft.Windows.GdiPlus" +
                       "_6595b64144ccf1df_1.0.0.0_x-ww_8D353f13\gdiplus.dll";

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:appendPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:appendPath);

gdiVer = GetVer(file:file, share:share);
if(!gdiVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 1" >< SP || "Service Pack 2" >< SP || "Service Pack 3" >< SP)
  {
    if(version_is_less_equal(version:gdiVer, test_version:"5.1.3097.0")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 1" >< SP || "Service Pack 2" >< SP)
  {
    if(version_is_less_equal(version:gdiVer, test_version:"5.1.3097.0")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
