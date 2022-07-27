###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2016-0010.nasl 11569 2018-09-24 10:29:54Z asteins $
#
# VMSA-2016-0010 (CVE-2016-5330) ESXi: VMware product updates address multiple important security issues
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
  script_oid("1.3.6.1.4.1.25623.1.0.105851");
  script_cve_id("CVE-2016-5330");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11569 $");
  script_name("VMSA-2016-0010 (CVE-2016-5330) ESXi: VMware product updates address multiple important security issues");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0010.html");

  script_tag(name:"vuldetect", value:"Checks for missing patches.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"A DLL hijacking vulnerability is present in the VMware Tools 'Shared Folders' (HGFS) feature running on Microsoft Windows. Exploitation of this
issue may lead to arbitrary code execution with the privileges of the victim. In order to exploit this issue, the attacker would need write access to a network share and they
would need to entice the local user into opening their document.

Successfully exploiting this issue requires installation of 'Shared Folders' component (HGFS feature) which does not get installed in 'custom/typical' installation of VMware Tools
on Windows VM running on ESXi.");

  script_tag(name:"affected", value:"ESXi 6.0 without patch ESXi600-201603102-SG

ESXi 5.5  without patch ESXi550-201607102-SG

ESXi 5.1  without patch ESXi510-201605102-SG

ESXi 5.0  without patch ESXi500-201606102-SG");

  script_tag(name:"last_modification", value:"$Date: 2018-09-24 12:29:54 +0200 (Mon, 24 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-05 16:10:53 +0200 (Fri, 05 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
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

patches = make_array( "6.0.0", "VIB:tools-light:6.0.0-1.31.3568943",
                      "5.5.0", "VIB:tools-light:5.5.0-3.86.4179631",
                      "5.1.0", "VIB:tools-light:5.1.0-3.82.3872638",
                      "5.0.0", "VIB:tools-light:5.0.0-3.87.3982819");

if( ! patches[esxVersion] ) exit( 0 );

if( _esxi_patch_missing( esxi_version:esxVersion, patch:patches[esxVersion] ) )
{
  security_message(port:0);
  exit(0);

}

exit(99);

