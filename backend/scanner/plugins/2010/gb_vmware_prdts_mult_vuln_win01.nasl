###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_mult_vuln_win01.nasl 14331 2019-03-19 14:03:05Z jschulte $
#
# VMware Products Multiple Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801319");
  script_version("$Revision: 14331 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:03:05 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1139", "CVE-2009-1564", "CVE-2009-1565");
  script_bugtraq_id(39345, 39363, 39364);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VMware Products Multiple Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36712");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-36/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/510643");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a heap-based buffer
  overflow via specially crafted video files containing incorrect framebuffer
  parameters.");
  script_tag(name:"affected", value:"VMware Server version 2.x,
  VMware Player version 2.5.x before 2.5.4 build 246459 and
  VMware Workstation version 6.5.x before 6.5.4 build 246459 on windows");
  script_tag(name:"insight", value:"The multiple flaws are due to

  - An integer truncation errors in 'vmnc.dll' when processing 'HexTile' encoded
    video chunks which can be exploited to cause heap-based buffer overflows.

  - A format string vulnerability in 'vmrun' allows users to gain privileges
    via format string specifiers in process metadata.");
  script_tag(name:"summary", value:"The host is installed with VMWare products and are prone to multiple
  vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to workstation version 6.5.4 build 246459,

  Upgrade to VMware player version 6.5.4 build 246459,

  Apply workaround for VMware Server version 2.x,

  *****
  NOTE: Ignore this warning, if above mentioned workaround is manually applied.
  *****");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer != NULL )
{
  if(version_in_range(version:vmplayerVer, test_version:"2.5", test_version2:"2.5.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer != NULL)
{
  if(version_in_range(version:vmworkstnVer, test_version:"6.5", test_version2:"6.5.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# VMware Server
vmserVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserVer)
{
  if(vmserVer =~ "^2.*"){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
