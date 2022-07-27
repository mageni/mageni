###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2016-0023_remote.nasl 11938 2018-10-17 10:08:39Z asteins $
#
# VMSA-2016-003: VMware ESXi updates address a cross-site scripting issue (remote check)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140101");
  script_cve_id("CVE-2016-7463");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_version("$Revision: 11938 $");

  script_name("VMSA-2016-003: VMware ESXi updates address a cross-site scripting issue (remote check)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0023.html");

  script_tag(name:"vuldetect", value:"Check the build number");

  script_tag(name:"insight", value:"The ESXi Host Client contains a vulnerability that may allow for stored cross-site scripting (XSS). The issue can be introduced by an attacker that has permission to manage virtual machines through ESXi Host Client or by tricking the vSphere administrator to import a specially crafted VM. The issue may be triggered on the system from where ESXi Host Client is used to manage the specially crafted VM.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware product updates address a critical glibc security vulnerability");

  script_tag(name:"affected", value:"ESXi 6.0 without patch ESXi600-201611102-SG
ESXi 5.5 without patch ESXi550-201612102-SG");

  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-21 16:22:14 +0100 (Wed, 21 Dec 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

 exit(0);

}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "6.0.0", "4558694",
                           "5.5.0", "4756874");


if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) )
{
  security_message( port:0, data: esxi_remote_report( ver:esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
  exit(0);
}

exit( 99 );

