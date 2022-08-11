###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2016-0014.nasl 11607 2018-09-25 13:53:15Z asteins $
#
# VMSA-2016-0014: VMware ESXi updates address multiple security issues
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
  script_oid("1.3.6.1.4.1.25623.1.0.105892");
  script_cve_id("CVE-2016-7081", "CVE-2016-7082", "CVE-2016-7083", "CVE-2016-7084", "CVE-2016-7079", "CVE-2016-7080", "CVE-2016-7085", "CVE-2016-7086");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11607 $");
  script_name("VMSA-2016-0014: VMware ESXi updates address multiple security issues");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0014.html");

  script_tag(name:"vuldetect", value:"Checks for missing patches.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The graphic acceleration functions used in VMware Tools for OSX handle memory incorrectly. Two resulting NULL pointer dereference vulnerabilities may allow for local privilege escalation on Virtual Machines that run OSX.
The issues can be remediated by installing a fixed version of VMware Tools on affected OSX   VMs directly. Alternatively the fixed version of Tools can be installed through ESXi or Fusion after first updating to a version of ESXi or Fusion that ships with a fixed version of VMware Tools.");

  script_tag(name:"last_modification", value:"$Date: 2018-09-25 15:53:15 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-09-16 11:58:28 +0200 (Fri, 16 Sep 2016)");
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

patches = make_array( "6.0.0", "VIB:tools-light:6.0.0-2.43.4192238",
                      "5.5.0", "VIB:tools-light:5.5.0-3.86.4179631");

if( ! patches[esxVersion] ) exit( 0 );

if( _esxi_patch_missing( esxi_version:esxVersion, patch:patches[esxVersion] ) )
{
  security_message(port:0);
  exit(0);

}

exit(99);

