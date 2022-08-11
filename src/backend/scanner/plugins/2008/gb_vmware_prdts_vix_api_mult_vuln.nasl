###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_vix_api_mult_vuln.nasl 12623 2018-12-03 13:11:38Z cfischer $
#
# VMware VIX API Multiple Buffer Overflow Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800007");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-09-29 16:48:05 +0200 (Mon, 29 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2100");
  script_bugtraq_id(29552);
  script_name("VMware VIX API Multiple Buffer Overflow Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30556");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2008-0009.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");

  script_tag(name:"affected", value:"VMware Player 1.x - before 1.0.7 build 91707 on Windows

  VMware Player 2.x - before 2.0.4 build 93057 on Windows

  VMware Server 1.x - before 1.0.6 build 91891 on Windows

  VMware Workstation 5.x - before 5.5.7 build 91707 on Windows

  VMware Workstation 6.x - before 6.0.4 build 93057 on Windows

  VMware ACE 2.x - before 2.0.4 build 93057 on Windows");

  script_tag(name:"insight", value:"VMware VIX API (Application Program Interface) fails to adequately bounds
  check user supplied input before copying it to insufficient size buffer.");

  script_tag(name:"summary", value:"The host is installed with VMWare product(s) that are vulnerable
  to multiple buffer overflow.");

  script_tag(name:"solution", value:"Upgrade VMware Product(s) to below version,

  VMware Player 1.0.7 build 91707 or 2.0.4 build 93057 or later

  VMware Server 1.0.6 build 91891 or later

  VMware Workstation 5.5.7 build 91707 or 6.0.4 build 93057 or later

  VMware ACE 2.0.4 build 93057");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to execute arbitrary code
  on the affected system and local user can obtain elevated privileges on the target system.

  Successful exploitation requires that the vix.inGuest.enable configuration
  value is enabled.");

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
  if(ereg(pattern:"^(1\.0(\.[0-6])?|2\.0(\.[0-3])?)$",
          string:vmplayerVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

vmserverVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserverVer)
{
  if(ereg(pattern:"^1\.0(\.[0-5])?$", string:vmserverVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer)
{
  if(ereg(pattern:"^(5\.([0-4](\..*)?|5(\.[0-6])?)|6\.0(\.[0-3])?)$",
          string:vmworkstnVer)){
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