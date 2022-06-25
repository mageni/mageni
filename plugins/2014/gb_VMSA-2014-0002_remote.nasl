###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2014-0002_remote.nasl 12419 2018-11-19 13:45:13Z cfischer $
#
# VMSA-2014-0002: VMware vSphere updates to third party libraries (remote check)
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
  script_oid("1.3.6.1.4.1.25623.1.0.103916");
  script_cve_id("CVE-2013-5211", "CVE-2013-4332");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12419 $");
  script_name("VMSA-2014-0002: VMware vSphere updates to third party libraries (remote check)");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 14:45:13 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-03-12 14:04:01 +0100 (Wed, 12 Mar 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0002.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"a. DDoS vulnerability in NTP third party libraries

  The NTP daemon has a DDoS vulnerability in the handling of the
  'monlist' command. An attacker may send a forged request to a
  vulnerable NTP server resulting in an amplified response to the
  intended target of the DDoS attack.

  b. Update to ESXi glibc package

  The ESXi glibc package is updated to version glibc-2.5-118.el5_10.2 to
  resolve a security issue.

  c. vCenter and Update Manager, Oracle JRE 1.7 Update 45

  Oracle JRE is updated to version JRE 1.7 Update 45, which addresses
  multiple security issues that existed in earlier releases of Oracle JRE.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware has updated vSphere third party libraries.");

  script_tag(name:"affected", value:"vCenter Server Appliance 5.5 prior to 5.5 Update 1

  VMware vCenter Server 5.5 prior 5.5 Update 1

  VMware Update Manager 5.5 prior 5.5 Update 1

  VMware ESXi 5.5 without patch ESXi550-201403101-SG.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "5.5.0", "1623387" );

if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) ) {
  security_message(port:0, data:esxi_remote_report( ver:esxVersion, build:esxBuild, fixed_build:fixed_builds[esxVersion] ) );
  exit(0);
}

exit( 99 );