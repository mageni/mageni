###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2013-0014.nasl 14186 2019-03-14 13:57:54Z cfischer $
#
# VMSA-2013-0014 VMware Workstation, Fusion, ESXi and ESX patches address a guest privilege escalation
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103851");
  script_cve_id("CVE-2013-3519");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 14186 $");
  script_name("VMSA-2013-0014 VMware Workstation, Fusion, ESXi and ESX patches address a guest privilege escalation");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0014.html");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:57:54 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-12-05 11:04:01 +0100 (Thu, 05 Dec 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_tag(name:"vuldetect", value:"Checks for missing patches.");

  script_tag(name:"insight", value:"a. VMware LGTOSYNC privilege escalation.

VMware ESX, Workstation and Fusion contain a vulnerability in the
handling of control code in lgtosync.sys. A local malicious user may
exploit this vulnerability to manipulate the memory allocation. This
could result in a privilege escalation on 32-bit Guest Operating
Systems running Windows 2000 Server, Windows XP or Windows 2003 Server
on ESXi and ESX, or Windows XP on Workstation and Fusion.

The vulnerability does not allow for privilege escalation from the
Guest Operating System to the host. This means that host memory can
not be manipulated from the Guest Operating System.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware Workstation, Fusion, ESXi and ESX patches
  address a vulnerability in the LGTOSYNC.SYS driver which could result
  in a privilege escalation on older Windows-based Guest Operating Systems.");

  script_tag(name:"affected", value:"VMware Workstation 9.x prior to version 9.0.3

  VMware Player 5.x prior to version 5.0.3

  VMware Fusion 5.x prior to version 5.0.4

  VMware ESXi 5.1 without patch ESXi510-201304102

  VMware ESXi 5.0 without patch ESXi500-201303102

  VMware ESXi 4.1 without patch ESXi410-201301402

  VMware ESXi 4.0 without patch ESXi400-201305401

  VMware ESX 4.1 without patch ESX410-201301401

  VMware ESX 4.0 without patch ESX400-201305401");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(!esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.0.0","ESXi400-201305401-SG",
                     "4.1.0","ESXi410-201301401-SG",
                     "5.0.0","VIB:tools-light:5.0.0-2.29.1022489",
                     "5.1.0","VIB:tools-light:5.1.0-0.11.1063671");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);