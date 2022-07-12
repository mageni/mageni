###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_prv_esc_vuln.nasl 12623 2018-12-03 13:11:38Z cfischer $
#
# VMware Product(s) Local Privilege Escalation Vulnerability
#
# Authors: Chandan S <schandan@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800006");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-09-26 14:12:58 +0200 (Fri, 26 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0967", "CVE-2008-2100");
  script_bugtraq_id(29552);
  script_name("VMware Product(s) Local Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");

  script_tag(name:"affected", value:"VMware Player 1.x - before 1.0.7 build 91707 on Linux

  VMware Player 2.x - before 2.0.4 build 93057 on Linux

  VMware Server 1.x - before 1.0.6 build 91891 on Linux

  VMware Workstation 5.x - before 5.5.7 build 91707 on Linux

  VMware Workstation 6.x - before 6.0.4 build 93057 on Linux");

  script_tag(name:"summary", value:"The host is installed with VMWare product(s) that are vulnerable
  to local privilege escalation vulnerability.");

  script_tag(name:"solution", value:"Upgrade VMware Product(s) to below version,

  VMware Player 1.0.7 build 91707 or 2.0.4 build 93057 or later

  VMware Server 1.0.6 build 91891 or later

  VMware Workstation 5.5.7 build 91707 or 6.0.4 build 93057 or later.");

  script_tag(name:"insight", value:"Issue is due to local exploitation of an untrusted library path in
  vmware-authd.

  VMware VIX API (Application Program Interface) fails to adequately bounds
  check user supplied input before copying it to insufficient size buffer.");

  script_tag(name:"impact", value:"Successful exploitation could result in arbitrary code execution
  on linux based host system by an unprivileged user and can also crash the
  application.

  Local access is required in order to execute the set-uid vmware-authd and
  Also, vix.inGuest.enable configuration must be set.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30556");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2008-0009.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if(!get_kb_item("VMware/Linux/Installed")){
  exit(0);
}

playerVer = get_kb_item("VMware/Player/Linux/Ver");
if(playerVer)
{
  if(ereg(pattern:"^(1\.0(\.[0-6])?|2\.0(\.[0-3])?)($|[^.0-9])",
          string:playerVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

serverVer = get_kb_item("VMware/Server/Linux/Ver");
if(serverVer)
{
  if(ereg(pattern:"^1\.0(\.[0-5])?($|[^.0-9])", string:serverVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

wrkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(wrkstnVer)
{
  if(ereg(pattern:"^(5\.([0-4](\..*)?|5(\.[0-6])?)|6\.0(\.[0-3])?)($|[^.0-9])",
          string:wrkstnVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
