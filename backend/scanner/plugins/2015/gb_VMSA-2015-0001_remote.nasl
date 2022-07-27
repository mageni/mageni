###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2015-0001_remote.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# VMSA-2015-0001: VMware vCenter Server, ESXi, Workstation, Player, and Fusion updates address security issues (remote check)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105191");
  script_cve_id("CVE-2014-8370", "CVE-2015-1043", "CVE-2015-1044", "CVE-2014-3513", "CVE-2014-3567", "CVE-2014-3566", "CVE-2014-3568", "CVE-2014-3660");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 11872 $");
  script_name("VMSA-2015-0001: VMware vCenter Server, ESXi, Workstation, Player, and Fusion updates address security issues (remote check)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0001.html");

  script_tag(name:"vuldetect", value:"Check the build number");

  script_tag(name:"insight", value:"a. VMware ESXi, Workstation, Player, and Fusion host privilege escalation vulnerability

VMware ESXi, Workstation, Player and Fusion contain an arbitrary file write issue. Exploitation this issue may allow for privilege
escalation on the host.

c. VMware ESXi, Workstation, and Player Denial of Service vulnerability

VMware ESXi, Workstation, and Player contain an input validation issue in VMware Authorization process (vmware-authd). This issue
may allow for a Denial of Service of the host. On VMware ESXi and on Workstation running on Linux the Denial of Service would be
partial.

d. Update to VMware vCenter Server and ESXi for OpenSSL 1.0.1 and 0.9.8 package

The OpenSSL library is updated to version 1.0.1j or 0.9.8zc to resolve multiple security issues.

e. Update to ESXi libxml2 package

The libxml2 library is updated to version libxml2-2.7.6-17 to resolve a security issue.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware vCenter Server, ESXi, Workstation, Player and Fusion address several security issues.");

  script_tag(name:"affected", value:"Mware Workstation 10.x prior to version 10.0.5
VMware Player 6.x prior to version 6.0.5
VMware Fusion 7.x prior to version 7.0.1
VMware Fusion 6.x prior to version 6.0.5
vCenter Server 5.5 prior to Update 2d
ESXi 5.5 without patch ESXi550-201403102-SG, ESXi550-201501101-SG
ESXi 5.1 without patch ESXi510-201404101-SG
ESXi 5.0 without patch ESXi500-201405101-SG");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-30 12:05:45 +0100 (Fri, 30 Jan 2015)");
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

fixed_builds = make_array( "5.0.0", "1749766",
                           "5.1.0", "1743201",
                           "5.5.0", "2352327");


if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) )
{
  security_message( port:0, data: esxi_remote_report( ver:esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
  exit(0);
}

exit( 99 );


exit(99);

