###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_tools_local_prv_esc_vuln_win.nasl 12604 2018-11-30 15:07:33Z cfischer $
#
# VMware Tools Local Privilege Escalation Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800004");
  script_version("$Revision: 12604 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 16:07:33 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-09-26 14:12:58 +0200 (Fri, 26 Sep 2008)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2007-5671");
  script_name("VMware Tools Local Privilege Escalation Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");

  script_tag(name:"insight", value:"An input validation error is present in the Windows-based VMware HGFS.sys
  driver. Exploitation of this flaw might result in arbitrary code execution
  on the guest system by an unprivileged guest user. The HGFS.sys driver is
  present in the guest operating system if the VMware Tools package is loaded
  on Windows based Guest OS.");

  script_tag(name:"summary", value:"The host is installed with VMWare product(s) that are vulnerable
  to local privilege escalation vulnerability.");

  script_tag(name:"affected", value:"VMware ACE 1.x - 1.0.5 build 79846 on Windows

  VMware Player 1.x - before 1.0.6 build 80404 on Windows

  VMware Server 1.x - before 1.0.5 build 80187 on Windows

  VMware Workstation 5.x - before 5.5.6 build 80404 on Windows");

  script_tag(name:"solution", value:"Upgrade VMware Product(s) to below version,

  VMware ACE 1.0.5 build 79846 or later

  VMware Player 1.0.6 build 80404 or later

  VMware Server 1.0.5 build 80187 or later

  VMware Workstation 5.5.6 build 80404 or later.");

  script_tag(name:"impact", value:"Successful exploitation could result in guest OS users to modify
  arbitrary memory locations in guest kernel memory and gain privileges.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30556");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2008-0009.html");

  exit(0);
}

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

vmaceVer = get_kb_item("VMware/ACE/Win/Ver");
if(!vmaceVer){
  vmaceVer = get_kb_item("VMware/ACE\Dormant/Win/Ver");
}

if(vmaceVer)
{
  if(ereg(pattern:"^1\.0(\.[0-4])?$", string:vmaceVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer)
{
  if(ereg(pattern:"^1\.0\.[0-5]($|\..*)", string:vmplayerVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

vmserverVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserverVer)
{
  if(ereg(pattern:"^1\.0(\.[0-4])?$", string:vmserverVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer)
{
  if(ereg(pattern:"^5\.([0-4](\..*)?|5(\.[0-5])?)$", string:vmworkstnVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
