##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openoffice_code_exec_vuln_win_900042.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# OpenOffice rtl_allocateMemory() Remote Code Execution Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900042");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-09-02 07:39:00 +0200 (Tue, 02 Sep 2008)");
  script_bugtraq_id(30866);
  script_cve_id("CVE-2008-3282");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("OpenOffice rtl_allocateMemory() Remote Code Execution Vulnerability (Windows)");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/31640/");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2449");

  script_tag(name:"summary", value:"This host has OpenOffice.Org installed, which is prone to remote
  code execution vulnerability.");

  script_tag(name:"insight", value:"The issue is due to a numeric truncation error within the rtl_allocateMemory()
  method in alloc_global.c file.");

  script_tag(name:"affected", value:"OpenOffice.org 2.4.1 and prior on Windows.");

  script_tag(name:"solution", value:"Upgrade to OpenOffice.org Version 3.2.0 or later.");

  script_tag(name:"impact", value:"Attackers can cause an out of bounds array access by tricking a
  user into opening a malicious document, also allow execution of arbitrary code.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://download.openoffice.org/index.html");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach item(registry_enum_keys(key:key)) {

  orgName = registry_get_sz(key:key + item, item:"DisplayName");

  if(orgName && "OpenOffice.org" >< orgName) {

    orgVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    # <= 2.4.9310 (ie., 2.4.1)
    if(orgVer && egrep(pattern:"^([01]\..*|2\.([0-3](\..*)?|4(\.([0-8]?[0-9]?[0-9]?[0-9]|9[0-2][0-9][0-9]|930[0-9]|9310))?))$", string:orgVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
    exit(99);
  }
}

exit(0);