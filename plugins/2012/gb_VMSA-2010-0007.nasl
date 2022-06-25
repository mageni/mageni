###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2010-0007.nasl 14187 2019-03-14 14:09:52Z cfischer $
#
# VMSA-2010-0007 VMware hosted products, vCenter Server and ESX patches resolve multiple security issues
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
  script_oid("1.3.6.1.4.1.25623.1.0.103467");
  script_cve_id("CVE-2010-1142", "CVE-2010-1140", "CVE-2009-2042", "CVE-2009-1564", "CVE-2009-1565",
                "CVE-2009-3732", "CVE-2009-3707", "CVE-2010-1138", "CVE-2010-1139", "CVE-2010-1141");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 14187 $");
  script_name("VMSA-2010-0007: VMware hosted products, vCenter Server and ESX patches resolve multiple security issues");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 15:09:52 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-04-16 10:53:01 +0100 (Mon, 16 Apr 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2010-0007.html");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2010-0007.");

  script_tag(name:"affected", value:"VMware Workstation 7.0,

  VMware Workstation 6.5.3 and earlier,

  VMware Player 3.0,

  VMware Player 2.5.3 and earlier,

  VMware ACE 2.6,

  VMware ACE 2.5.3 and earlier,

  VMware Server 2.0.2 and earlier,

  VMware Fusion 3.0,

  VMware Fusion 2.0.6 and earlier,

  VMware VIX API for Windows 1.6.x,

  VMware ESXi 4.0 before patch ESXi400-201002402-BG

  VMware ESXi 3.5 before patch ESXe350-200912401-T-BG

  VMware ESX 4.0 without patches ESX400-201002401-BG, ESX400-200911223-UG

  VMware ESX 3.5 without patch ESX350-200912401-BG

  VMware ESX 3.0.3 without patch ESX303-201002203-UG

  VMware ESX 2.5.5 without Upgrade Patch 15.");

  script_tag(name:"impact", value:"a. Windows-based VMware Tools Unsafe Library Loading vulnerability

  In order for an attacker to exploit the vulnerability, the attacker would need to lure the user that is logged on a Windows Guest
  Operating System to click on the attacker's file on a network share. This file could be in any file format. The attacker will need
  to have the ability to host their malicious files on a network share.

  b. Windows-based VMware Tools Arbitrary Code Execution vulnerability

  In order for an attacker to exploit the vulnerability, the attacker would need to be able to plant their malicious executable in a
  certain location on the Virtual Machine of the user. On most recent versions of Windows (XP, Vista) the attacker would need to have
  administrator privileges to plant the malicious executable in the right location.

  c. Windows-based VMware Workstation and Player host privilege escalation

  In order for an attacker to exploit the vulnerability, the attacker would need to be able to plant their malicious executable in a
  certain location on the host machine.  On most recent versions of Windows (XP, Vista) the attacker would need to have administrator
  privileges to plant the malicious executable in the right location.

  e. VMware VMnc Codec heap overflow vulnerabilities

  Vulnerabilities in the decoder allow for execution of arbitrary code with the privileges of the user running an application
  utilizing the vulnerable codec.

  For an attack to be successful the user must be tricked into visiting a malicious web page or opening a malicious video file on
  a system that has the vulnerable version of the VMnc codec installed.

  f. VMware Remote Console format string vulnerability

  For an attack to be successful, an attacker would need to trick the VMrc user into opening a malicious Web page or following a malicious
  URL. Code execution would be at the privilege level of the user.

  h. Potential information leak via hosted networking stack

  A guest operating system could send memory from the host vmware-vmx process to the virtual network adapter and potentially to the
  host's physical Ethernet wire.

  i. Linux-based vmrun format string vulnerability

  If a vmrun command is issued and processes are listed, code could be executed in the context of the user listing the processes.");

  script_tag(name:"insight", value:"VMware hosted products, vCenter Server and ESX patches resolve multiple security issues:

  a. Windows-based VMware Tools Unsafe Library Loading vulnerability

  A vulnerability in the way VMware libraries are referenced allows for arbitrary code execution in the context of the logged on user.
  This vulnerability is present only on Windows Guest Operating Systems.

  b. Windows-based VMware Tools Arbitrary Code Execution vulnerability

  A vulnerability in the way VMware executables are loaded allows for arbitrary code execution in the context of the logged on user.
  This vulnerability is present only on Windows Guest Operating Systems.

  c. Windows-based VMware Workstation and Player host privilege escalation

  A vulnerability in the USB service allows for a privilege escalation. A local attacker on the host of a Windows-based Operating
  System where VMware Workstation or VMware Player is installed could plant a malicious executable on the host and elevate their
  privileges.

  d. Third party library update for libpng to version 1.2.37

  The libpng libraries through 1.2.35 contain an uninitialized-memory-read bug that may have security implications. Specifically,
  1-bit (2-color) interlaced images whose widths are not divisible by 8 may result in several uninitialized bits at the end of
  certain rows in certain interlace passes being returned to the user. An application that failed to mask these out-of-bounds
  pixels might display or process them, albeit presumably with benign results in most cases.

  e. VMware VMnc Codec heap overflow vulnerabilities

  f. VMware Remote Console format string vulnerability

  VMware Remote Console (VMrc) contains a format string vulnerability. Exploitation of this issue may lead to arbitrary code execution on
  the system where VMrc is installed.

  Under the following two conditions your version of VMrc is likely to be affected:

  - the VMrc plug-in was obtained from vCenter 4.0 or from ESX 4.0 without patch ESX400-200911223-UG and

  - VMrc is installed on a Windows-based system

  g. Windows-based VMware authd remote denial of service

  A vulnerability in vmware-authd could cause a denial of service condition on Windows-based hosts. The denial of service is limited
  to a crash of authd.

  h. Potential information leak via hosted networking stack

  A vulnerability in the virtual networking stack of VMware hosted products could allow host information disclosure.

  i. Linux-based vmrun format string vulnerability

  A format string vulnerability in vmrun could allow arbitrary code execution.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc"); # Used in _esxi_patch_missing()
include("vmware_esx.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.0.0","ESXi400-201002402-BG");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);