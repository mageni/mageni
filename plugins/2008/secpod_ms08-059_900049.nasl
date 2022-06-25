##############################################################################
# OpenVAS Vulnerability Test
# Description: Host Integration Server RPC Service Remote Code Execution Vulnerability (956695)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900049");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)");
  script_bugtraq_id(31620);
  script_cve_id("CVE-2008-3466");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Host Integration Server RPC Service Remote Code Execution Vulnerability (956695)");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-059.mspx");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to bypass the
  authentication mechanism and can access administrative functionalities via
  a specially crafted RPC request.");
  script_tag(name:"affected", value:"Microsoft Host Integration Server 2000/2004/2006 (Server) on Windows.
  Microsoft Host Integration Server 2000/2004 (Client) on Windows.");
  script_tag(name:"insight", value:"The issue is due to an error in the SNA Remote Procedure Call (RPC) service.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-059.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Host Integration Server")){
  exit(0);
}

if(hotfix_missing(name:"956695") == 0){
  exit(0);
}

hisPath = registry_get_sz(item:"Path",
          key:"SOFTWARE\Microsoft\Host Integration Server\ConfigFramework");
if(!hisPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:hisPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:hisPath + "system\Snarpcsv.exe");

hisVer = GetVer(file:file, share:share);
if(ereg(pattern:"^7\.0\.([01]?[0-9]?[0-9]?[0-9]|2[0-8][0-9][0-9])\.0$",
        string:hisVer)){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}
