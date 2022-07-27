###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vcenter_VMSA-2016-0005.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# VMSA-2016-0005 VMware product updates address critical and important security issues
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
  script_oid("1.3.6.1.4.1.25623.1.0.105731");
  script_cve_id("CVE-2016-3427", "CVE-2016-2077");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 14181 $");
  script_name("VMSA-2016-0005 VMware product updates address critical and important security issues");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0005.html");

  script_tag(name:"vuldetect", value:"Check the build number");

  script_tag(name:"insight", value:"The RMI server of Oracle JRE JMX deserializes any class when deserializing
  authentication credentials. This may allow a remote, unauthenticated attacker to cause deserialization flaws
  and execute their commands.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"Mware product updates address critical and important security issues.");

  script_tag(name:"affected", value:"vCenter Server 6.0 on Windows without workaround of KB 2145343

  vCenter Server 6.0 on Linux (VCSA) prior to 6.0.0b

  vCenter Server 5.5 prior to 5.5 U3d (on Windows), 5.5 U3 (VCSA)

  vCenter Server 5.1 prior to 5.1 U3b

  vCenter Server 5.0 prior to 5.0 U3e");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-26 11:51:22 +0200 (Thu, 26 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");

 exit(0);

}
include("vmware_esx.inc");
include("version_func.inc");
include("host_details.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version") ) exit( 0 );
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build") ) exit( 0 );

if( vcenter_version == "5.0.0" )
  if ( int( vcenter_build ) < int( 3073236 ) ) fix = '5.0 U3e (+ KB 2144428 on Windows)';

if( vcenter_version == "5.1.0" )
  if ( int( vcenter_build ) < int( 3070521 ) ) fix = '5.1 U3d / 5.1 U3b with KB 2144428 on Windows';

if( vcenter_version == "6.0.0" )
  if ( int( vcenter_build ) < int( 2776510 ) ) fix = '6.0.0b (+ KB 2145343 on Windows)';

if( host_runs( "Windows" ) == "yes" )
{
  if( vcenter_version == "5.5.0" )
    if ( int( vcenter_build ) < int( 3252642 ) ) fix = '5.5 U3d / 5.5 U3b + KB 2144428';
}
else if( host_runs( "Linux" ) == "yes" )
{
  if( vcenter_version == "5.5.0" )
    if ( int( vcenter_build ) < int( 3000241 ) ) fix = '5.5 U3';
}

if( fix )
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build:fix, typ:'vCenter' ) );
  exit(0);
}

exit(99);