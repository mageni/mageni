##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_flexcell_activex_file_overwrire_vuln_900406.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: FlexCell Grid Control ActiveX Arbitrary File Overwrite Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900406");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-5404");
  script_bugtraq_id(32443);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_name("FlexCell Grid Control ActiveX Arbitrary File Overwrite Vulnerability");

  script_xref(name:"URL", value:"http://www.grid2000.com");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32829");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes.");
  script_tag(name:"insight", value:"The vulnerability is due to an error in the 'httpDownloadFile' method
  in the 'FlexCell.ocx' component file.");
  script_tag(name:"summary", value:"This host is installed with FlexCell Grid Control ActiveX and is
  prone to arbitrary File Overwrite vulnerability.");
  script_tag(name:"affected", value:"FlexCell Grid Control ActiveX 5.7.1 and prior on all Windows Platform.

  Workaround:
  Set the killbit for the affected ActiveX control.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

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

entries = registry_enum_keys(key:key);
foreach item (entries)
{
  flexcellName = registry_get_sz(key:key + item, item:"DisplayName");
  if("FlexCell Grid Control" >< flexcellName)
  {
    if(egrep(pattern:"^([0-4]\..*|5\.[0-6](\..*)?|5\.7(\.[01])?)$",
             string:registry_get_sz(key:key + item, item:"DisplayVersion"))){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
