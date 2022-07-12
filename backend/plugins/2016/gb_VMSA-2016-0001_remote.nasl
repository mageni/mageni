###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2016-0001_remote.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# VMSA-2016-0001 VMware ESXi, Fusion, Player, and Workstation updates address important guest privilege escalation vulnerability (remote check)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105509");
  script_cve_id("CVE-2015-6933");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_version("$Revision: 14181 $");
  script_name("VMSA-2016-0001 VMware ESXi, Fusion, Player, and Workstation updates address important guest privilege escalation vulnerability (remote check)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0001.html");

  script_tag(name:"vuldetect", value:"Check the build number");

  script_tag(name:"insight", value:"A kernel memory corruption vulnerability is present in the VMware Tools 'Shared Folders' (HGFS) feature running on Microsoft Windows.
  Successful exploitation of this issue could lead to an escalation of privilege in the guest operating system.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware ESXi, Fusion, Player, and Workstation updates address important guest privilege escalation vulnerability");

  script_tag(name:"affected", value:"VMware ESXi 6.0 without patch ESXi600-201512102-SG

  VMware ESXi 5.5 without patch ESXi550-201512102-SG

  VMware ESXi 5.1 without patch ESXi510-201510102-SG

  VMware ESXi 5.0 without patch ESXi500-201510102-SG");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-14 10:45:54 +0100 (Thu, 14 Jan 2016)");

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

fixed_builds = make_array( "5.0.0", "3021432",
                           "5.1.0", "3021178",
                           "5.5.0", "3247226",
                           "6.0.0", "3341439");

if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) )
{
  security_message( port:0, data: esxi_remote_report( ver:esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
  exit(0);
}

exit( 99 );