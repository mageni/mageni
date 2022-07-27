###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2014-0001.nasl 14185 2019-03-14 13:43:25Z cfischer $
#
# VMSA-2014-0001: VMware Workstation, Player, Fusion, ESXi, ESX and vCloud Director address several security issues
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103884");
  script_cve_id("CVE-2014-1207", "CVE-2014-1208", "CVE-2014-1211");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 14185 $");
  script_name("VMSA-2014-0001 VMware Workstation, Player, Fusion, ESXi, ESX and vCloud Director address several security issues");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0001.html");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:43:25 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-20 10:04:01 +0100 (Mon, 20 Jan 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_tag(name:"vuldetect", value:"Checks for missing patches.");

  script_tag(name:"insight", value:"a. VMware ESXi and ESX NFC NULL pointer dereference

VMware ESXi and ESX contain a NULL pointer dereference in the handling
of the Network File Copy (NFC) traffic. To exploit this vulnerability,
an attacker must intercept and modify the NFC traffic between
ESXi/ESX and the client. Exploitation of the issue may lead to a
Denial of Service.

To reduce the likelihood of exploitation, vSphere components should be
deployed on an isolated management network.

b. VMware VMX process denial of service vulnerability

Due to a flaw in the handling of invalid ports, it is possible to
cause the VMX process to fail. This vulnerability may allow a guest
user to affect the VMX process resulting in a partial denial of
service on the host.

c. VMware vCloud Director Cross Site Request Forgery (CSRF)

VMware vCloud Director contains a vulnerability in the Hyper Text
Transfer Protocol (http) session management. An attacker may trick
an authenticated user to click a malicious link, which would result
in the user being logged out. The user is able to immediately log
back into the system.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware Workstation, Player, Fusion, ESXi, ESX and vCloud Director address several security issues.");

  script_tag(name:"affected", value:"VMware Workstation 9.x prior to version 9.0

VMware Player 5.x prior to version 5.0

VMware Fusion 5.x prior to version 5.0

VMware ESXi 5.1 without patch ESXi510-201401101

VMware ESXi 5.0 without patch ESXi500-201310101

VMware ESXi 4.1 without patch ESXi410-201312401

VMware ESXi 4.0 without patch ESXi400-201310401

VMware ESX 4.1 without patch ESX410-201312401

VMware ESX 4.0 without patch ESX400-201310401

vCloud Director 5.1.x prior to version 5.1.3");
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
                     "5.1.0","VIB:esx-base:5.1.0-1.22.1483097");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_message(port:0);
  exit(0);

}

exit(99);