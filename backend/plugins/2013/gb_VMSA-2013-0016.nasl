###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2013-0016.nasl 11096 2018-08-23 12:49:10Z mmartin $
#
# VMSA-2013-0016 VMware ESXi and ESX unauthorized file access through vCenter Server and ESX
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103863");
  script_cve_id("CVE-2013-5973");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11096 $");
  script_name("VMSA-2013-0016 VMware ESXi and ESX unauthorized file access through vCenter Server and ESX");


  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0016.html");

  script_tag(name:"last_modification", value:"$Date: 2018-08-23 14:49:10 +0200 (Thu, 23 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-12-27 10:04:01 +0100 (Fri, 27 Dec 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_tag(name:"vuldetect", value:"Checks for missing patches.");
  script_tag(name:"insight", value:"a. VMware ESXi and ESX unauthorized file access through vCenter Server and ESX

VMware ESXi and ESX contain a vulnerability in the handling of certain Virtual
Machine file descriptors. This issue may allow an unprivileged vCenter Server
user with the privilege 'Add Existing Disk' to obtain read and write access to
arbitrary files on ESXi or ESX. On ESX, an unprivileged local user may obtain
read and write access to arbitrary files. Modifying certain files may allow
for code execution after a host reboot.

Unpriviledged vCenter Server users or groups that are assigned the predefined
role 'Virtual Machine Power User' or 'Resource Pool Administrator' have the
privilege 'Add Existing Disk'.

The issue cannot be exploited through VMware vCloud Director.

Workaround

A workaround is provided in VMware Knowledge Base article 2066856.

Mitigation

In a default vCenter Server installation no unprivileged users or groups
are assigned the predefined role 'Virtual Machine Power User' or 'Resource
Pool Administrator'.  Restrict the number of vCenter Server users that have
the privilege 'Add Existing Disk'.");
  script_tag(name:"solution", value:"Apply the missing patch(es).");
  script_tag(name:"summary", value:"VMware ESXi and ESX unauthorized file access through vCenter Server and ESX");
  script_tag(name:"affected", value:"VMware ESXi 5.5 without patch ESXi550-201312001
VMware ESXi 5.1 without patch ESXi510-201310001
VMware ESXi 5.0 without patch update-from-esxi5.0-5.0_update03
VMware ESXi 4.1 without patch ESXi410-201312001
VMware ESXi 4.0 without patch ESXi400-201310001

VMware ESX 4.1 without patch ESX410-201312001
VMware ESX 4.0 without patch ESX400-201310001");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

 exit(0);

}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(!esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.0.0","ESXi400-201310401-SG",
                     "4.1.0","ESXi410-201312401-SG",
                     "5.0.0","VIB:esx-base:5.0.0-2.38.1311177",
                     "5.1.0","VIB:esx-base:5.1.0-1.19.1312874",
                     "5.5.0","VIB:esx-base:5.5.0-0.7.1474526");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_message(port:0);
  exit(0);

}

exit(99);

