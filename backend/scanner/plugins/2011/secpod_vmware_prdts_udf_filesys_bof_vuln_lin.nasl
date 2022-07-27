###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vmware_prdts_udf_filesys_bof_vuln_lin.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# VMware Products UDF File Systems Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902490");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-3868");
  script_bugtraq_id(49942);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-17 15:10:19 +0530 (Thu, 17 Nov 2011)");
  script_name("VMware Products UDF File Systems Buffer Overflow Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46241");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1026139");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2011-0011.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execution of arbitrary code.");
  script_tag(name:"affected", value:"Vmware Player version 3.0 before 3.1.5,
  VMware Workstation version 7.0 before 7.1.5");
  script_tag(name:"insight", value:"The flaw is due to an error when handling UDF filesystem images.This can be
  exploited to cause a buffer overflow via a specially crafted ISO image file.");
  script_tag(name:"summary", value:"The host is installed with VMWare products and are prone to
  buffer overflow vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Vmware Player version 3.1.5 or later  Upgrade to Vmware Workstation version 7.1.5 or later");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2011-0011.html");
  exit(0);
}


include("version_func.inc");

if(!get_kb_item("VMware/Linux/Installed")){
  exit(0);
}

vmplayerVer = get_kb_item("VMware/Player/Linux/Ver");
if(vmplayerVer != NULL )
{
  if(version_in_range(version:vmplayerVer, test_version:"3.0", test_version2:"3.1.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmworkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(vmworkstnVer != NULL)
{
  if(version_in_range(version:vmworkstnVer, test_version:"7.0", test_version2:"7.1.4")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
