###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2011-0009.nasl 11696 2018-09-28 21:16:43Z cfischer $
#
# VMSA-2011-0009.3 VMware hosted product updates, ESX patches and VI Client update resolve multiple security issues
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
  script_oid("1.3.6.1.4.1.25623.1.0.103452");
  script_cve_id("CVE-2009-4536", "CVE-2010-1188", "CVE-2009-3080", "CVE-2010-2240", "CVE-2011-2146", "CVE-2011-1787", "CVE-2011-2145", "CVE-2011-2217");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11696 $");
  script_name("VMSA-2011-0009.3 VMware hosted product updates, ESX patches and VI Client update resolve multiple security issues");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 23:16:43 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-16 10:41:24 +0100 (Fri, 16 Mar 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2011-0009.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2011-0009.3.");

  script_tag(name:"affected", value:"VMware Workstation 7.1.3 and earlier

  VMware Player 3.1.3 and earlier

  VMware Fusion 3.1.2 and earlier

  ESXi 5.0 without patch ESXi500-201112403-SG

  ESXi 4.1 without patches ESXi410-201104402-BG and ESXi410-201110201-SG

  ESXi 4.0 without patch ESXi400-201110401-SG

  ESXi 3.5 without patches ESXe350-201105401-I-SG and ESXe350-201105402-T-SG

  ESX 4.1 without patches ESX410-201104401-SG and ESX410-201110225-SG.

  ESX 4.0 without patch ESX400-201104401-SG and ESX400-201110410-SG

  ESX 3.5 without patches ESX350-201105401-SG, ESX350-201105404-SG and ESX350-201105406-SG");

  script_tag(name:"insight", value:"VMware hosted product updates, ESX patches and VI Client update resolve multiple security issues.

  a. VMware vmkernel third party e1000(e) Driver Packet Filter Bypass

  There is an issue in the e1000(e) Linux driver for Intel PRO/1000 adapters that allows a remote attacker to bypass packet filters.

  b. ESX third party update for Service Console kernel

  This update for the console OS kernel package resolves four security issues.

  IPv4 Remote Denial of Service An remote attacker can achieve a denial of service via an issue in the kernel IPv4 code.

  SCSI Driver Denial of Service / Possible Privilege Escalation A local attacker can achieve a denial of service
  and possibly a privilege escalation via a vulnerability in the Linux SCSI drivers.

  Kernel Memory Management Arbitrary Code Execution A context-dependent attacker can execute arbitrary code via a
  vulnerability in a kernel memory handling function.

  e1000 Driver Packet Filter Bypass There is an issue in the Service Console e1000 Linux driver for Intel PRO/1000
  adapters that allows a remote attacker to bypass packet filters.

  c. Multiple vulnerabilities in mount.vmhgfs

  This patch provides a fix for the following three security issues in the VMware Host Guest File System (HGFS).
  None of these issues affect Windows based Guest Operating Systems.

  Mount.vmhgfs Information Disclosure Information disclosure via a vulnerability that allows an attacker with access
  to the Guest to determine if a path exists in the Host filesystem and whether it is a file or directory regardless
  of permissions.

  Mount.vmhgfs Race Condition Privilege escalation via a race condition that allows an attacker with access to the guest
  to mount on arbitrary directories in the Guest filesystem and achieve privilege escalation if they can control the
  contents of the mounted directory.

  Mount.vmhgfs Privilege Escalation Privilege escalation via a procedural error that allows an attacker with access to the
  guest operating system to gain write access to an arbitrary file in the Guest filesystem. This issue only affects Solaris
  and FreeBSD Guest Operating Systems.

  d. VI Client ActiveX vulnerabilities

  VI Client COM objects can be instantiated in Internet Explorer which may cause memory corruption. An attacker who succeeded
  in making the VI Client user visit a malicious Web site could execute code on the user's system within the security context
  of that user.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.1.0","ESXi410-201110201-SG",
                     "4.0.0","ESXi400-201110401-SG",
                     "5.0.0","VIB:net-e1000:8.0.3.1-2vmw.500.0.3.515841");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);