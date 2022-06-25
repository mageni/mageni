###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_tools_local_prv_esc_vuln_lin.nasl 12623 2018-12-03 13:11:38Z cfischer $
#
# VMware Tools Local Privilege Escalation Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800005");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-09-26 14:12:58 +0200 (Fri, 26 Sep 2008)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2007-5671");
  script_name("VMware Tools Local Privilege Escalation Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");

  script_tag(name:"insight", value:"An input validation error is present in the Windows-based VMware HGFS.sys
  driver. Exploitation of this flaw might result in arbitrary code execution
  on the guest system by an unprivileged guest user. The HGFS.sys driver is
  present in the guest operating system if the VMware Tools package is loaded on Windows based Guest OS.");

  script_tag(name:"summary", value:"The host is installed with VMWare product(s) that are vulnerable
  to local privilege escalation vulnerability.");

  script_tag(name:"affected", value:"VMware Player 1.x - before 1.0.6 build 80404 on Linux

  VMware Server 1.x - before 1.0.5 build 80187 on Linux

  VMware Workstation 5.x - before 5.5.6 build 80404 on Linux");

  script_tag(name:"solution", value:"Upgrade VMware Product(s) to below version,

  VMware Player 1.0.6 build 80404 or later

  VMware Server 1.0.5 build 80187 or later

  VMware Workstation 5.5.6 build 80404 or later.");

  script_tag(name:"impact", value:"Successful exploitation could result in guest OS users to modify arbitrary
  memory locations in guest kernel memory and gain privileges.

  Issue still exists even if the host has HGFS disabled and has no shared folders.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30556");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2008-0009.html");

  exit(0);
}

playerVer = get_kb_item("VMware/Player/Linux/Ver");
if(playerVer)
{
  if(ereg(pattern:"^1\.0(\.[0-5])?($|[^.0-9])", string:playerVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

serverVer = get_kb_item("VMware/Server/Linux/Ver");
if(serverVer)
{
  if(ereg(pattern:"^1\.0(\.[0-4])?($|[^.0-9])", string:serverVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

wrkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(wrkstnVer)
{
  if(ereg(pattern:"^5\.([0-4](\..*)?|5(\.[0-5])?)($|[^.0-9])", string:wrkstnVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
