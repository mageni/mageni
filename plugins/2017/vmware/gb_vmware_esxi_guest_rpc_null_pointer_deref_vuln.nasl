###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_esxi_guest_rpc_null_pointer_deref_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# VMware ESXi Guest RPC Null Pointer Dereference Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811840");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-4925");
  script_bugtraq_id(100842);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-22 12:05:44 +0530 (Fri, 22 Sep 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("VMware ESXi Guest RPC Null Pointer Dereference Vulnerability");

  script_tag(name:"summary", value:"The host is installed with VMware ESXi
  and is prone to a NULL pointer dereference vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling
  guest RPC requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  with normal user privileges to crash their VMs.");

  script_tag(name:"affected", value:"VMware ESXi 6.5 before ESXi650-201707101-SG.
  VMware ESXi 6.0 before ESXi600-201706101-SG.
  VMware ESXi 5.5 before ESXi550-201709101-SG.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2017-0015.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");
  script_xref(name:"URL", value:"http://www.vmware.com");
  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );

## https://esxi-patches.v-front.de/ESXi-6.5.0.html
## https://esxi-patches.v-front.de/ESXi-6.0.0.html
## https://esxi-patches.v-front.de/ESXi-5.5.0.html
patches = make_array("6.5.0", "VIB:esx-base:6.5.0-0.23.5969300",
                     "6.0.0", "VIB:esx-base:6.0.0-3.66.5485776",
                     "5.5.0", "VIB:esx-base:5.5.0-3.103.6480267");

if( ! patches[esxVersion] ) exit( 0 );

## https://esxi-patches.v-front.de/ESXi-6.5.0.html
if( _esxi_patch_missing( esxi_version:esxVersion, patch:patches[esxVersion] ) )
{
  report = report_fixed_ver(installed_version:esxVersion, fixed_version:patches[esxVersion]);
  security_message(data:report, port:0);
  exit(0);
}
