###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2014-0005.nasl 12419 2018-11-19 13:45:13Z cfischer $
#
# VMSA-2014-0005: VMware Workstation, Player, Fusion, and ESXi patches address a guest privilege escalation
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
  script_oid("1.3.6.1.4.1.25623.1.0.105037");
  script_cve_id("CVE-2014-3793");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12419 $");
  script_name("VMSA-2014-0005: VMware Workstation, Player, Fusion, and ESXi patches address a guest privilege escalation");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0005.html");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 14:45:13 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-06-02 11:04:01 +0100 (Mon, 02 Jun 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"a. Guest privilege escalation in VMware Tools
  A kernel NULL dereference vulnerability was found in VMware Tools
  running on Microsoft Windows 8.1. Successful exploitation of this
  issue could lead to an escalation of privilege in the guest operating
  system.

  The vulnerability does not allow for privilege escalation from the
  Guest Operating System to the host. This means that host memory can
  not be manipulated from the Guest Operating System.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware Workstation, Player, Fusion, and ESXi patches address a
  vulnerability in VMware Tools which could result in a privilege escalation on Microsoft Windows 8.1.");

  script_tag(name:"affected", value:"ESXi 5.5 without patch ESXi550-201403102-SG

  ESXi 5.1 without patch ESXi510-201404102-SG

  ESXi 5.0 without patch ESXi500-201405102-SG.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if( ! get_kb_item( "VMware/ESXi/LSC" ) ) exit( 0 );
if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );

patches = make_array( "5.5.0", "VIB:tools-light:5.5.0-0.14.1598313",
                      "5.1.0", "VIB:tools-light:5.1.0-2.27.1743201",
                      "5.0.0", "VIB:tools-light:5.0.0-3.47.1749766" );

if( ! patches[esxVersion] ) exit( 0 );

if( _esxi_patch_missing( esxi_version:esxVersion, patch:patches[esxVersion] ) ){
  security_message(port:0);
  exit(0);
}

exit(99);