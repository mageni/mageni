###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2012-0007.nasl 11696 2018-09-28 21:16:43Z cfischer $
#
# VMSA-2012-0007 VMware hosted products and ESX patches address privilege escalation
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103466");
  script_cve_id("CVE-2012-1518");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11696 $");
  script_name("VMSA-2012-0007 VMware hosted products and ESX patches address privilege escalation");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 23:16:43 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-04-13 10:53:01 +0100 (Fri, 13 Apr 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2012-0007.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2012-0007.");

  script_tag(name:"affected", value:"Workstation 8.0.1 and earlier

  Player 4.0.1 and earlier

  Fusion 4.1.1 and earlier

  ESXi 5.0 without patch ESXi500-201203102-SG

  ESXi 4.1 without patch ESXi410-201201402-BG

  ESXi 4.0 without patch ESXi400-201203402-BG

  ESXi 3.5 without patch ESXe350-201203402-T-BG

  ESX 4.1 without patch ESX410-201201401-SG

  ESX 4.0 without patch ESX400-201203401-SG

  ESX 3.5 without patch ESX350-201203402-BG");

  script_tag(name:"insight", value:"VMware hosted products and ESXi/ESX patches address privilege escalation.

  a. VMware Tools Incorrect Folder Permissions Privilege Escalation

  The access control list of the VMware Tools folder is incorrectly set.
  Exploitation of this issue may lead to local privilege escalation on
  Windows-based Guest Operating Systems.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.1.0","ESXi410-201201402-BG",
                     "4.0.0","ESXi400-201203402-BG",
                     "5.0.0","VIB:tools-light:5.0.0-0.10.608089");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);