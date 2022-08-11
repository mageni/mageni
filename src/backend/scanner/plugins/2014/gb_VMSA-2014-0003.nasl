###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2014-0003.nasl 11194 2018-09-03 12:44:14Z mmartin $
#
# VMSA-2014-0003: VMware vSphere Client updates address security vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105012");
  script_cve_id("CVE-2014-1209", "CVE-2014-1210");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11194 $");
  script_name("VMSA-2014-0003 VMware vSphere Client updates address security vulnerabilities");


  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0003.html");

  script_tag(name:"last_modification", value:"$Date: 2018-09-03 14:44:14 +0200 (Mon, 03 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-04-24 13:04:01 +0100 (Thu, 24 Apr 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_tag(name:"vuldetect", value:"Checks for missing patches.");
  script_tag(name:"insight", value:"a. vSphere Client Insecure Client Download

vSphere Client contains a vulnerability in accepting an updated vSphere Client
file from an untrusted source. The vulnerability may allow a host to direct
vSphere Client to download and execute an arbitrary file from any URI. This
issue can be exploited if the host has been compromised or if a user has been
tricked into clicking a malicious link.");
  script_tag(name:"solution", value:"Apply the missing patch(es).");
  script_tag(name:"summary", value:"VMware vSphere Client updates address security vulnerabilities");
  script_tag(name:"affected", value:"vSphere Client 5.1
vSphere Client 5.0
vSphere Client 4.1
vSphere Client 4.0");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

 exit(0);

}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(!esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.0.0","ESXi400-201402402-SG",
                     "4.1.0","ESXi410-201404401-SG");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_message(port:0);
  exit(0);

}

exit(99);

