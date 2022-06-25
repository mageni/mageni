###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_mult_loc_prev_escl_vuln_lin.nasl 11553 2018-09-22 14:22:01Z cfischer $
#
# VMware Products Multiple Local Privilege Escalation Vulnerabilities (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801559");
  script_version("$Revision: 11553 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)");
  script_cve_id("CVE-2010-4295", "CVE-2010-4296");
  script_bugtraq_id(45167, 45168);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("VMware Products Multiple Local Privilege Escalation Vulnerabilities (Linux)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42453/");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2010-0018.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2010/000112.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
code with elevated privileges, this may aid in other attacks.");
  script_tag(name:"affected", value:"VMware Server version  2.x
VMware Player 3.x before 3.1.2 build 301548
VMware Workstation 7.x before 7.1.2 build 301548 on Linux");
  script_tag(name:"insight", value:"The flaws are due to

  - Race conditions within the 'vmware-mount' utility when handling temporary
   files during the mounting process can be exploited to create files or
   directories.

  - An error within the 'vmware-mount' utility when loading libraries that can
   be exploited to execute arbitrary code with root privileges.");
  script_tag(name:"summary", value:"The host is installed with VMWare products multiple local
privilege escalation Vulnerabilities.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}


include("version_func.inc");

if(!get_kb_item("VMware/Linux/Installed")){
  exit(0);
}

vmplayerVer = get_kb_item("VMware/Player/Linux/Ver");
if(vmplayerVer != NULL )
{
  if(version_in_range(version:vmplayerVer, test_version:"3.0", test_version2:"3.1.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmworkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(vmworkstnVer != NULL)
{
  if(version_in_range(version:vmworkstnVer, test_version:"7.0", test_version2:"7.1.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# VMware Server
vmserVer = get_kb_item("VMware/Server/Linux/Ver");
if(vmserVer)
{
  if(vmserVer =~ "^2.*"){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
