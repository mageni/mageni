###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2014-0012_remote.nasl 12419 2018-11-19 13:45:13Z cfischer $
#
# VMSA-2014-0012: VMware vSphere product updates address security vulnerabilities (remote check)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105134");
  script_cve_id("CVE-2014-3797", "CVE-2014-8371", "CVE-2013-2877", "CVE-2014-0191", "CVE-2014-0015",
                "CVE-2014-0138", "CVE-2013-1752", "CVE-2013-4238");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("$Revision: 12419 $");
  script_name("VMSA-2014-0012: VMware vSphere product updates address security vulnerabilities (remote check)");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 14:45:13 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-12-05 11:32:51 +0100 (Fri, 05 Dec 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0012.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"a. VMware vCSA cross-site scripting vulnerability
  VMware vCenter Server Appliance (vCSA) contains a vulnerability that may
  allow for Cross Site Scripting. Exploitation of this vulnerability in
  vCenter Server requires tricking a user to click on a malicious link or
  to open a malicious web page while they are logged in into vCenter.

  b. vCenter Server certificate validation issue
  vCenter Server does not properly validate the presented certificate
  when establishing a connection to a CIM Server residing on an ESXi
  host. This may allow for a Man-in-the-middle attack against the CIM service.

  c. Update to ESXi libxml2 package
  libxml2 is updated to address multiple security issues.

  d. Update to ESXi Curl package
  Curl is updated to address multiple security issues.

  e. Update to ESXi Python package
  Python is updated to address multiple security issues.

  f. vCenter and Update Manager, Oracle JRE 1.6 Update 81

  Oracle has documented the CVE identifiers that are addressed in JRE
  1.6.0 update 81 in the Oracle Java SE Critical Patch Update Advisory
  of July 2014.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware vSphere product updates address a Cross Site Scripting issue, a certificate validation
  issue and security vulnerabilities in third-party libraries.");

  script_tag(name:"affected", value:"VMware vCenter Server Appliance 5.1 Prior to Update 3

  VMware vCenter Server 5.5 prior to Update 2

  VMware vCenter Server 5.1 prior to Update 3

  VMware vCenter Server 5.0 prior to Update 3c

  VMware ESXi 5.1 without patch ESXi510-201412101-SG");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "5.1.0", "2323231" );

if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) ) {
  security_message( port:0, data:esxi_remote_report( ver:esxVersion, build:esxBuild, fixed_build:fixed_builds[esxVersion] ) );
  exit( 0 );
}

exit( 99 );