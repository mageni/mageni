###############################################################################
# OpenVAS Vulnerability Test
#
# Bluetooth Stack Could Allow Remote Code Execution Vulnerability (951376)
#
# Authors: Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800008");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-09-30 14:16:17 +0200 (Tue, 30 Sep 2008)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-1453");
  script_bugtraq_id(29522);
  script_name("Bluetooth Stack Could Allow Remote Code Execution Vulnerability (951376)");
  script_xref(name:"URL", value:"http://www.us-cert.gov/cas/techalerts/TA08-162B.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-030.mspx");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code with elevated privileges by rapidly sending a large number
  of specially crafted SDP (Service Discovery Protocol) packets to the
  vulnerable system.");

  script_tag(name:"affected", value:"Microsoft Windows XP SP2/SP3.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-030.");

  script_tag(name:"insight", value:"The flaw is due to an error in the Bluetooth stack when processing
  large number of service description requests.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# well but, not supported at this point in time.
if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

sysFile = smb_get_system32root();
if(!sysFile){
  exit(0);
}

sysFile += "\drivers\Bthport.sys";

if(hotfix_missing(name:"951376") == 0){
  exit(0);
}

SP = get_kb_item("SMB/WinXP/ServicePack");
if("Service Pack 2" >< SP)
{
  sysVer = get_version(dllPath:sysFile, string:"prod", offs:260000);
  if(sysVer == NULL){
    exit(0);
  }

  if(egrep(pattern:"^5\.0?1\.2600\.([0-2]?[0-9]?[0-9]?[0-9]|3[0-2][0-9][0-9]" +
                   "|33([0-7][0-9]|8[0-8]))$",
           string:sysVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if("Service Pack 3" >< SP)
{
  sysVer = get_version(dllPath:sysFile, string:"prod", offs:260000);
  if(sysVer == NULL){
      exit(0);
  }

  if(egrep(pattern:"5\.0?1\.2600\.([0-4]?[0-9]?[0-9]?[0-9]|5[0-5][0-9][0-9]|" +
                   "56[01][0-9])$",
           string:sysVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
