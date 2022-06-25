##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_rtcp_remote_dos_vuln_900404.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: Microsoft Windows RTCP Unspecified Remote DoS Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900404");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-5179");
  script_bugtraq_id(32341);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Microsoft Windows RTCP Unspecified Remote DoS Vulnerability");
  script_xref(name:"URL", value:"http://www.voipshield.com/research-details.php?id=132");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will crash the application.");
  script_tag(name:"affected", value:"Microsoft Windows Live Messenger version 8.5.1302.1018 and prior.");
  script_tag(name:"insight", value:"The vulnerability is due to error in the 'RTCP' or
  'Real-time Transport Control Protocol' receiver report packet handling.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Microsoft Live Messenger and is prone to
  remote Denial of Service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://windows.microsoft.com/en-us/windows-live/essentials");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

entries = registry_enum_keys(key:key);
if(entries == NULL){
  exit(0);
}

foreach item (entries)
{
  if("Windows Live Messenger" >< registry_get_sz(key:key + item, item:"DisplayName"))
  {
    if((egrep(pattern:"^([0-7]\..*|8\.[0-4](\..*)?|8\.5(\.([0-9]?[0-9]?[0-9]" +
                      "|1[0-2]?[0-9]?[0-9]?|130[01])(\..*)?|\.1302)?(\.[0-9]" +
                      "?[0-9]?[0-9]|\.100[0-9]|\.101[0-8])?)?$",
              string:registry_get_sz(key:key + item, item:"DisplayVersion")))){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
