###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_inguest_prv_esc_vuln_win.nasl 12623 2018-12-03 13:11:38Z cfischer $
#
# VMware Products Trap Flag In-Guest Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800071");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-12-15 15:44:51 +0100 (Mon, 15 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4915", "CVE-2008-4917");
  script_bugtraq_id(32168);
  script_name("VMware Products Trap Flag In-Guest Privilege Escalation Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/3052");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2008-0018.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");

  script_tag(name:"affected", value:"VMware Server 1.x - 1.0.7 on Windows

  VMware ACE 1.x - 1.0.7 and 2.x - 2.0.5 on Windows

  VMware Player 1.x - 1.0.8 and 2.x - 2.0.5 on Windows

  VMware Workstation 6.0.5 and earlier on all Windows");

  script_tag(name:"insight", value:"The issue is due to an error in the CPU hardware emulation while
  handling the trap flag.");

  script_tag(name:"summary", value:"The host is installed with VMWare product(s) that are vulnerable
  to privilege escalation vulnerability.");

  script_tag(name:"solution", value:"Upgrade VMware to the latest version.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to execute arbitrary code
  on the affected system and users could bypass certain security restrictions or can gain escalated privileges.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

vmserverVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserverVer)
{
  if(version_is_less_equal(version:vmserverVer, test_version:"1.0.7")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer)
{
  if(version_is_less_equal(version:vmplayerVer, test_version:"1.0.8"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
  else if(version_in_range(version:vmplayerVer, test_version:"2.0",
          test_version2:"2.0.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer)
{
  if(version_in_range(version:vmworkstnVer, test_version:"5.0",
                      test_version2:"5.5.8"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
  else if(version_in_range(version:vmworkstnVer, test_version:"6.0",
          test_version2:"6.0.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

vmaceVer = get_kb_item("VMware/ACE/Win/Ver");
if(!vmaceVer){
  vmaceVer = get_kb_item("VMware/ACE\Dormant/Win/Ver");
}

if(vmaceVer)
{
  if(version_is_less_equal(version:vmaceVer, test_version:"1.0.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
  else if(version_in_range(version:vmaceVer, test_version:"2.0",
          test_version2:"2.0.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
