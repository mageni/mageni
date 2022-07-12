###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SMB Signing Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902797");
  script_version("2019-05-03T12:31:27+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-04-02 16:53:51 +0530 (Mon, 02 Apr 2012)");
  script_name("Microsoft SMB Signing Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/916846");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain sensitive
  information.");
  script_tag(name:"affected", value:"Microsoft Windows XP Service Pack 2 and prior
  Microsoft Windows 2003 Service Pack 1 and prior");
  script_tag(name:"insight", value:"The flaw is due to disabling SMB signing. Malicious users could sniff
  network traffic, capture, and reply to SMB transactions that are not signed
  by performing a man-in-the-middle (MITM) attack to obtain sensitive
  information.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is disabled SMB signing and is prone to information
  disclosure vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(xp:3, win2003:2) <= 0){
  exit(0);
}

## Client
key = "SYSTEM\CurrentControlSet\Services\lanmanworkstation\parameters";
if(registry_key_exists(key:key))
{
  val1 = registry_get_dword(key:key, item:"enablesecuritysignature");
  val2 = registry_get_dword(key:key, item:"requiresecuritysignature");

  if(val1 == "0" && val2 == "0")
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## Server
key2 = "SYSTEM\CurrentControlSet\Services\lanmanserver\parameters";
if(!registry_key_exists(key:key2)){
  exit(0);
}

val3 = registry_get_dword(key:key2, item:"enablesecuritysignature");
val4 = registry_get_dword(key:key2, item:"requiresecuritysignature");

if(val3 == "0" && val4 == "0"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
