###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2016-0023.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# VMSA-2016-0023: VMware ESXi updates address a cross-site scripting issue
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140100");
  script_cve_id("CVE-2016-7463");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_version("$Revision: 12338 $");
  script_name("VMSA-2016-0023: VMware ESXi updates address a cross-site scripting issue");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0023.html");

  script_tag(name:"vuldetect", value:"Checks for missing patches.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The ESXi Host Client contains a vulnerability that may allow for stored cross-site scripting (XSS). The issue can be introduced by an attacker that has permission to manage virtual machines through ESXi Host Client or by tricking the vSphere administrator to import a specially crafted VM. The issue may be triggered on the system from where ESXi Host Client is used to manage the specially crafted VM.");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-21 15:46:45 +0100 (Wed, 21 Dec 2016)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

 exit(0);

}

include("vmware_esx.inc");
include("version_func.inc");

if( ! get_kb_item( 'VMware/ESXi/LSC' ) ) exit( 0 );
if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );

patches = make_array( "6.0.0", "VIB:esx-ui:1.9.0-4392584",
                      "5.5.0", "VIB:esx-ui:1.12.0-4722375");

if( ! patches[esxVersion] ) exit( 0 );

if( _esxi_patch_missing( esxi_version:esxVersion, patch:patches[esxVersion] ) )
{
  security_message(port:0);
  exit(0);

}

exit(99);

