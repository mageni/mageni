###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vcenter_VMSA-2015_0007.nasl 11259 2018-09-06 08:28:49Z mmartin $
#
# VMSA-2015-0007 VMware vCenter Server Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105395");
  script_cve_id("CVE-2015-5177", "CVE-2015-2342", "CVE-2015-1047");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11259 $");
  script_name("VMSA-2015-0007 VMware vCenter Server Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0007.html");

  script_tag(name:"vuldetect", value:"Check the build number");

  script_tag(name:"insight", value:"Mware ESXi OpenSLP Remote Code Execution
VMware ESXi contains a double free flaw in OpenSLP's SLPDProcessMessage() function. Exploitation of this issue may allow an unauthenticated attacker to execute code remotely on the ESXi host.

VMware vCenter Server JMX RMI Remote Code Execution
VMware vCenter Server contains a remotely accessible JMX RMI service that is not securely configured. An unauthenticated remote attacker that is able to connect to the service may be able use it to execute arbitrary code on the vCenter server.

VMware vCenter Server vpxd denial-of-service vulnerability
VMware vCenter Server does not properly sanitize long heartbeat messages. Exploitation of this issue may allow an unauthenticated attacker to create a denial-of-service condition in the vpxd service.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware vCenter Server JMX RMI Remote Code Execution / vpxd denial-of-service vulnerability");

  script_tag(name:"affected", value:"VMware ESXi 5.5 without patch ESXi550-201509101
VMware ESXi 5.1 without patch ESXi510-201510101
VMware ESXi 5.0 without patch ESXi500-201510101

VMware vCenter Server 6.0 prior to version 6.0 update 1
VMware vCenter Server 5.5 prior to version 5.5 update 3
VMware vCenter Server 5.1 prior to version 5.1 update u3b
VMware vCenter Server 5.0 prior to version 5.u update u3e");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-09-06 10:28:49 +0200 (Thu, 06 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-10-05 11:16:27 +0200 (Mon, 05 Oct 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_detect.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");

 exit(0);

}
include("vmware_esx.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version") ) exit( 0 );
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build") ) exit( 0 );

fixed_builds = make_array( "5.0.0","3073236",
                           "5.1.0","3070521",
                           "5.5.0","3000241",
                           "6.0.0","3040890");

if ( ! fixed_builds[ vcenter_version] ) exit( 0 );

if ( int( vcenter_build ) < int( fixed_builds[ vcenter_version ] ) )
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build: fixed_builds[vcenter_version], typ:'vCenter' ) );
  exit(0);
}

exit(99);

