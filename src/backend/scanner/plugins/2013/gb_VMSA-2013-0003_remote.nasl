###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2013-0003_remote.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# VMSA-2013-0003 VMware vCenter Server, ESXi and ESX address an NFC Protocol memory corruption and third party library security issues (remote check).
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
  script_oid("1.3.6.1.4.1.25623.1.0.103849");
  script_cve_id("CVE-2013-1659", "CVE-2012-2110");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11865 $");
  script_name("VMSA-2013-0003 VMware vCenter Server, ESXi and ESX address an NFC Protocol memory corruption and third party library security issues. (remote check)");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-03 15:04:01 +0100 (Tue, 03 Dec 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  script_tag(name:"vuldetect", value:"Check the build number.");
  script_tag(name:"insight", value:"VMware has updated VMware vCenter Server, ESXi and ESX to address
a vulnerability in the Network File Copy (NFC) Protocol. This update
also addresses multiple security vulnerabilities in third party
libraries used by VirtualCenter, ESX and ESXi.

Problem Description

a. VMware vCenter, ESXi and ESX NFC protocol memory corruption
   vulnerability

VMware vCenter Server, ESXi and ESX contain a vulnerability in the
handling of the Network File Copy (NFC) protocol. To exploit this
vulnerability, an attacker must intercept and modify the NFC
traffic between vCenter Server and the client or ESXi/ESX and the
client.  Exploitation of the issue may lead to code execution.

To reduce the likelihood of exploitation, vSphere components should
be deployed on an isolated management network.

b. VirtualCenter, ESX and ESXi Oracle (Sun) JRE update 1.5.0_38

Oracle (Sun) JRE is updated to version 1.5.0_38, which addresses
multiple security issues that existed in earlier releases of
Oracle (Sun) JRE.

Oracle has documented the CVE identifiers that are addressed
in JRE 1.5.0_38 in the Oracle Java SE Critical Patch Update
Advisory of October 2012.

c. Update to ESX service console OpenSSL RPM

The service console OpenSSL RPM is updated to version
openssl-0.9.7a.33.28.i686 to resolve multiple security issues.");
  script_tag(name:"solution", value:"Apply the missing patch(es).");
  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2013-0003.");
  script_tag(name:"affected", value:"VMware vCenter Server 5.1 prior to 5.1.0b
VMware vCenter Server 5.0 prior to 5.0 Update 2
VMware vCenter Server 4.0 prior to Update 4b
VMware VirtualCenter 2.5 prior to Update 6c

VMware ESXi 5.1 without ESXi510-201212101-SG
VMware ESXi 5.0 without ESXi500-201212102-SG
VMware ESXi 4.1 without ESXi410-201301401-SG
VMware ESXi 4.0 without ESXi400-201302401-SG
VMware ESXi 3.5 without ESXe350-201302401-I-SG and ESXe350-201302403-C-SG

VMware ESX 4.1 without ESX410-201301401-SG
VMware ESX 4.0 without ESX400-201302401-SG
VMware ESX 3.5 without ESX350-201302401-SG");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2013/000205.html");
  exit(0);
}

include("vmware_esx.inc");

if(!esxVersion = get_kb_item("VMware/ESX/version"))exit(0);
if(!esxBuild = get_kb_item("VMware/ESX/build"))exit(0);

fixed_builds = make_array("5.0.0","912577",
                          "5.1.0","911593");

if(!fixed_builds[esxVersion])exit(0);

if(int(esxBuild) < int(fixed_builds[esxVersion])) {

  security_message(port:0, data: esxi_remote_report(ver:esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion]));
  exit(0);
}

exit(99);
