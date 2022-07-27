###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2012-0018.nasl 11696 2018-09-28 21:16:43Z cfischer $
#
# VMSA-2012-0018: VMware security updates for vCSA and ESXi
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
  script_oid("1.3.6.1.4.1.25623.1.0.103627");
  script_cve_id("CVE-2012-6324", "CVE-2012-6325", "CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0830", "CVE-2011-1089", "CVE-2011-4609", "CVE-2012-0864", "CVE-2012-3404", "CVE-2012-3405", "CVE-2012-3406", "CVE-2012-3480");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11696 $");
  script_name("VMSA-2012-0018: VMware security updates for vCSA and ESXi");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 23:16:43 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-12-27 10:42:13 +0100 (Thu, 27 Dec 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2012-0018.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2012-0018.");

  script_tag(name:"affected", value:"vCenter Server Appliance 5.1 prior to vCSA 5.1.0b

  vCenter Server Appliance 5.0 prior to vCSA 5.0 Update 2

  VMware ESXi 5.1 without patch ESXi510-201212101

  VMware ESXi 5.0 without patch ESXi500-201212101");

  script_tag(name:"insight", value:"VMware has updated vCenter Server Appliance (vCSA) and ESX to address multiple security vulnerabilities:

  a. vCenter Server Appliance directory traversal

  The vCenter Server Appliance (vCSA) contains a directory traversal vulnerability that allows an
  authenticated remote user to retrieve arbitrary files. Exploitation of this issue may expose
  sensitive information stored on the server.

  b. vCenter Server Appliance arbitrary file download

  The vCenter Server Appliance (vCSA) contains an XML parsing vulnerability that allows an
  authenticated remote user to retrieve arbitrary files. Exploitation of this issue may
  expose sensitive information stored on the server.

  c. Update to ESX glibc package

  The ESX glibc package is updated to version glibc-2.5-81.el5_8.1 to resolve multiple security issues.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("5.0.0","VIB:esx-base:5.0.0-1.25.912577",
                     "5.1.0","VIB:esx-base:5.1.0-0.8.911593");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);