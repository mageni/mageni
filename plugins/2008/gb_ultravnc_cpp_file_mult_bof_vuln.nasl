###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ultravnc_cpp_file_mult_bof_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# UltraVNC VNCViewer Multiple Buffer Overflow Vulnerabilities - Nov08
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_xref(name:"URL", value:"http://secunia.com/advisories/28804");
  script_xref(name:"URL", value:"http://forum.ultravnc.info/viewtopic.php?p=45150");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/0486/products");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=571174;group_id=63887");
  script_oid("1.3.6.1.4.1.25623.1.0.800131");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-11-14 10:43:16 +0100 (Fri, 14 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5001");
  script_bugtraq_id(27687);
  script_name("UltraVNC VNCViewer Multiple Buffer Overflow Vulnerabilities - Nov08");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code
  by tricking a user into connecting to a malicious VNC server or by sending
  specially crafted data to a vncviewer in LISTENING mode and can even cause
  denial of service condition.");
  script_tag(name:"affected", value:"UltraVNC VNCViewer Version 1.0.2 and 1.0.4 before RC11 on Windows (Any).");
  script_tag(name:"insight", value:"The flaw is due to multiple boundary errors within the
  vncviewer/FileTransfer.cpp file, while processing malformed data.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to latest Version or
  Apply the available patch");
  script_tag(name:"summary", value:"This host is installed with UltraVNC VNCViewer and is prone to
  Buffer Overflow Vulnerability.");
  script_xref(name:"URL", value:"http://downloads.sourceforge.net/ultravnc/UltraVNC-Viewer-104-Security-Update-2---Feb-8-2008.zip");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  vncName = registry_get_sz(item:"DisplayName", key:key +item);
  if("UltraVNC" >!< vncName){
    continue;
  }

  vncComp = registry_get_sz(item:"Inno Setup: Selected Components",
                            key:key + item);
  if("viewer" >< vncComp)
  {
    vncPath = registry_get_sz(item:"InstallLocation", key:key +item);
    if(!vncPath){
      exit(0);
    }

    vncPath += "vncviewer.exe";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:vncPath);
    file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:vncPath);

    vncVer = GetVer(file:file, share:share);
    if(!vncVer){
      exit(0);
    }

    if(vncVer == "1.1.0.2"){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    else if ("1.0.4" >< vncVer)
    {
      report = string("NOTE: Ignore this report if above " +
                      "mentioned patch is already applied.\n  ***** \n");
      security_message(data:report);
    }
    exit(0);
  }
}
