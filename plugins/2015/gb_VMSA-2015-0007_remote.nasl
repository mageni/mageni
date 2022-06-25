###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2015-0007_remote.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# VMSA-2015-0007: VMware ESXi OpenSLP Remote Code Execution (remote check)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105394");
  script_cve_id("CVE-2015-5177", "CVE-2015-2342", "CVE-2015-1047");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11872 $");

  script_name("VMSA-2015-0007: VMware ESXi OpenSLP Remote Code Execution (remote check)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0007.html");

  script_tag(name:"vuldetect", value:"Check the build number");

  script_tag(name:"insight", value:"VMware ESXi OpenSLP Remote Code Execution
VMware ESXi contains a double free flaw in OpenSLP's SLPDProcessMessage() function. Exploitation of this issue may allow an unauthenticated attacker to execute code remotely on the ESXi host.

VMware vCenter Server JMX RMI Remote Code Execution
VMware vCenter Server contains a remotely accessible JMX RMI service that is not securely configured. An unauthenticated remote attacker that is able to connect to the service may be able use it to execute arbitrary code on the vCenter server.

VMware vCenter Server vpxd denial-of-service vulnerability
VMware vCenter Server does not properly sanitize long heartbeat messages. Exploitation of this issue may allow an unauthenticated attacker to create a denial-of-service condition in the vpxd service.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware vCenter and ESXi updates address critical security issues.");

  script_tag(name:"affected", value:"VMware ESXi 5.5 without patch ESXi550-201509101
VMware ESXi 5.1 without patch ESXi510-201510101
VMware ESXi 5.0 without patch ESXi500-201510101

VMware vCenter Server 6.0 prior to version 6.0 update 1
VMware vCenter Server 5.5 prior to version 5.5 update 3
VMware vCenter Server 5.1 prior to version 5.1 update u3b
VMware vCenter Server 5.0 prior to version 5.u update u3e");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-05 10:47:03 +0200 (Mon, 05 Oct 2015)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

 exit(0);

}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "5.0.0", "3021432",
                           "5.1.0", "3021178",
                           "5.5.0", "3029944");


if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) )
{
  security_message( port:0, data: esxi_remote_report( ver:esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
  exit(0);
}

exit( 99 );

