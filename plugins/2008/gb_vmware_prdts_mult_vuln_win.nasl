###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_mult_vuln_win.nasl 12623 2018-12-03 13:11:38Z cfischer $
#
# VMCI/HGFS VmWare Code Execution Vulnerability (Windows)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800002");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-09-25 10:10:31 +0200 (Thu, 25 Sep 2008)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2098", "CVE-2008-2099");
  script_bugtraq_id(29443);
  script_name("VMCI/HGFS VmWare Code Execution Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30476/");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2008-0008.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");

  script_tag(name:"affected", value:"VMware ACE/Player 2.0.x - 2.0.3 on all Windows

  VMware Workstation 6.0.x - 6.0.3 on all Windows");

  script_tag(name:"summary", value:"The host is installed with VMWare product(s) that are vulnerable
  to arbitrary code execution.");

  script_tag(name:"solution", value:"Upgrade VMware to below versions,

  VMware Workstation 6.0.4 or later.

  VMware Player/ACE 2.0.4 or later.");

  script_tag(name:"insight", value:"VMCI is an optional feature that allows communication with one another.
  This vulnerability allows the guest systems to execute arbitrary code on
  the host in the context of vmx process. The issue affects Windows based VMWare hosts only.

  VMware Host Guest File System (HGFS) shared folders feature allows users
  to transfer data between a guest operating system and the host operating
  system. A heap buffer overflow exists in VMware HGFS which allows guest
  system to execute code in the context of vmx process on the host.
  The issue exists only when VMWare system has shared folder enabled.

  Successful exploitation requires that the vix.inGuest.enable configuration
  value is enabled");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to execute arbitrary code
  on the affected system and users could bypass certain security restrictions or can gain escalated privileges.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer)
{
  if(ereg(pattern:"^(2\.0\.[0-3])($|\..*)", string:vmplayerVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer)
{
  if(ereg(pattern:"^6\.0(\.[0-3])?$", string:vmworkstnVer)){
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
  if(ereg(pattern:"^2\.0(\.[0-3])?$", string:vmaceVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}