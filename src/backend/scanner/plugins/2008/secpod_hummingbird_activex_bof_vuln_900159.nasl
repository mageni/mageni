##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hummingbird_activex_bof_vuln_900159.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: Hummingbird HostExplorer ActiveX Control BOF Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900159");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-10-21 15:08:20 +0200 (Tue, 21 Oct 2008)");
  script_cve_id("CVE-2008-4729");
  script_bugtraq_id(31783);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Denial of Service");
  script_name("Hummingbird HostExplorer ActiveX Control BOF Vulnerability");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6761");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32319/");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will allow execution arbitrary code, and deny the
  service.");

  script_tag(name:"affected", value:"Hummingbird HostExplorer versions prior to 2008 on Windows (all)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to HostExplorer 2008.");

  script_tag(name:"summary", value:"This host has Hummingbird HostExplorer ActiveX Control installed
  and is prone to stack based buffer overflow vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to error in Hummingbird.XWebHostCtrl.1 ActiveX control in
  hclxweb.dll file when handling the 'PlainTextPassword' function, which can be exploited by assigning an overly long string.");

  exit(0);
}

include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

hostExpVer = registry_get_sz(key:"SOFTWARE\Hummingbird\Event Monitoring" +
                                 "\Product Info\HostExplorer 2008" ,
                             item:"Version");
if(!hostExpVer){
  hostExpVer = registry_get_sz(key:"SOFTWARE\Hummingbird\Event Monitoring" +
                                   "\Product Info\HostExplorer 2008\HostExplorer",
                               item:"Version");
  if(!hostExpVer){
    exit(0);
  }
}

if(ereg(pattern:"^(([0-9]|1[0-2])(\..*)?)($|[^.0-9])", string:hostExpVer)){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
