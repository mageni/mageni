###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_orbital_viewer_mult_bof_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Orbital Viewer File Processing Buffer Overflow Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900755");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-0688");
  script_bugtraq_id(38436);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Orbital Viewer File Processing Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38720");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0478");
  script_xref(name:"URL", value:"http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-011-orbital-viewer-orb-buffer-overflow/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause buffer
overflow and execute arbitrary code on the system by tricking a user into
opening a malicious file or cause the affected application to crash.");
  script_tag(name:"affected", value:"Orbital Viewer version 1.04");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host has Orbital Viewer installed and is prone
to buffer overflow vulnerabilities.

Vulnerabilities Insight:
The flaw is due to error within the processing of '.orb' and '.ov' files,
which can be exploited to cause a stack-based buffer overflow when a user is
tricked into opening a specially crafted '.orb' or '.ov' file.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Orbital Viewer";
orbitName = registry_get_sz(key:key, item:"DisplayName");

if("Orbital Viewer" >< orbitName)
{
  orbitPath = registry_get_sz(key:key + item, item:"UninstallString");
  if(orbitPath != NULL)
  {
    share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:orbitPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:orbitPath -
                                "\UNINST.EXE" + "\ov.exe");
    orbitVer = GetVer(share:share, file:file);
    if(orbitVer != NULL)
    {
      if(version_is_less_equal(version:orbitVer, test_version:"1.0.0.2")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
