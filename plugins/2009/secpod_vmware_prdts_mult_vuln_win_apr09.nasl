###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Products Multiple Vulnerabilities (Windows) Apr09
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900704");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-05-18 09:48:30 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4916", "CVE-2008-3761", "CVE-2009-1146", "CVE-2009-1147",
                "CVE-2009-0909", "CVE-2009-0910", "CVE-2009-0177", "CVE-2009-1244");
  script_bugtraq_id(34373, 34471);
  script_name("VMware Products Multiple Vulnerabilities (Windows) Apr09");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0944");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2009-0005.html");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2009-0006.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2009/000055.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2009/000054.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause denial of service,
  local password information disclosure, arbitrary code execution, access to shared
  resources or heap overflow.");
  script_tag(name:"affected", value:"VMware Workstation 6.5.1 and prior

  VMware Player 2.5.1 and prior

  VMware Server 2.0.1 and prior");
  script_tag(name:"insight", value:"For detailed information of the multiple vulnerabilities please refer to the
  links provided in references.");
  script_tag(name:"summary", value:"The host is installed with VMWare products and are prone to
  Multiple Vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade your VMWare product according to the referenced vendor announcement.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer != NULL)
{
  if(version_is_less_equal(version:vmplayerVer, test_version:"2.5.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer != NULL)
{
  if(version_is_less_equal(version:vmworkstnVer, test_version:"6.5.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

vmserverVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserverVer != NULL)
{
  if(version_in_range(version:vmserverVer, test_version:"1.0", test_version2:"1.0.8") ||
     version_in_range(version:vmserverVer, test_version:"2.0", test_version2:"2.0.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
