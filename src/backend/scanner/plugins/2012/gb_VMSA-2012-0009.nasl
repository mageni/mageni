###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2012-0009.nasl 11696 2018-09-28 21:16:43Z cfischer $
#
# VMSA-2012-0009 VMware Workstation, Player, ESXi and ESX patches address critical security issues
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
  script_oid("1.3.6.1.4.1.25623.1.0.103481");
  script_cve_id("CVE-2012-1516", "CVE-2012-1517", "CVE-2012-2448", "CVE-2012-2449", "CVE-2012-2450");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 11696 $");
  script_name("VMSA-2012-0009 VMware Workstation, Player, ESXi and ESX patches address critical security issues");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 23:16:43 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-05-03 18:53:01 +0100 (Thu, 03 May 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2012-0009.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).

  a. VMware host memory overwrite vulnerability (data pointers)

  Workaround

  Configure virtual machines to use less than 4 GB of memory. Virtual machines
  that have less than 4GB of memory are not affected.

  Mitigation

  Do not allow untrusted users access to your virtual machines. Root or
  Administrator level permissions are not required to exploit this issue.

  b. VMware host memory overwrite vulnerability (function pointers)

  Workaround

  None identified

  Mitigation

  Do not allow untrusted users access to your virtual machines. Root or
  Administrator level permissions are not required to exploit this issue.

  c. ESX NFS traffic parsing vulnerability

  Workaround

  None identified

  Mitigation

  - Connect only to trusted NFS servers

  - Segregate the NFS network

  - Harden your NFS server

  d. VMware floppy device out-of-bounds memory write

  Workaround

  Remove the virtual floppy drive from the list of virtual IO devices. The VMware
  hardening guides recommend removing unused virtual IO devices in general.

  Mitigation

  Do not allow untrusted root users in your virtual machines. Root or
  Administrator level permissions are required to exploit this issue.

  e. VMware SCSI device unchecked memory write

  Workaround

  Remove the virtual SCSI controller from the list of virtual IO devices. The
  VMware hardening guides recommend removing unused virtual IO devices in
  general.

  Mitigation

  Do not allow untrusted root users access to your virtual machines. Root or
  Administrator level permissions are required to exploit this issue.");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2012-0009.");

  script_tag(name:"affected", value:"Workstation 8.0.2

  Player 4.0.2

  Fusion 4.1.2

  ESXi 5.0 without patch ESXi500-201205401-SG

  ESXi 4.1 without patches ESXi410-201205401-SG, ESXi410-201110201-SG, ESXi410-201201401-SG

  ESXi 4.0 without patches ESXi400-201105201-UG, ESXi400-201205401-SG

  ESXi 3.5 without patch ESXe350-201205401-I-SG

  ESX 4.1 without patches ESX410-201205401-SG, ESX410-201110201-SG, ESX410-201201401-SG

  ESX 4.0 without patches ESX400-201105201-UG, ESX400-201205401-SG

  ESX 3.5 without patch ESX350-201205401-SG");

  script_tag(name:"insight", value:"VMware Workstation, Player, ESXi and ESX patches address critical security issues:

  a. VMware host memory overwrite vulnerability (data pointers)

  Due to a flaw in the handler function for RPC commands, it is possible to
  manipulate data pointers within the VMX process. This vulnerability may allow a
  guest user to crash the VMX process or potentially execute code on the host.

  b. VMware host memory overwrite vulnerability (function pointers)

  Due to a flaw in the handler function for RPC commands, it is possible to
  manipulate function pointers within the VMX process. This vulnerability may
  allow a guest user to crash the VMX process or potentially execute code on the
  host.

  c. ESX NFS traffic parsing vulnerability

  Due to a flaw in the handling of NFS traffic, it is possible to overwrite
  memory. This vulnerability may allow a user with access to the network to
  execute code on the ESXi/ESX host without authentication. The issue is not
  present in cases where there is no NFS traffic.

  d. VMware floppy device out-of-bounds memory write

  Due to a flaw in the virtual floppy configuration it is possible to perform an
  out-of-bounds memory write. This vulnerability may allow a guest user to crash
  the VMX process or potentially execute code on the host.

  e. VMware SCSI device unchecked memory write

  Due to a flaw in the SCSI device registration it is possible to perform an
  unchecked write into memory. This vulnerability may allow a guest user to crash
  the VMX process or potentially execute code on the host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.1.0","ESXi410-201205401-SG",
                     "4.0.0","ESXi400-201205401-SG",
                     "5.0.0","VIB:esx-base:5.0.0-1.13.702118");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);