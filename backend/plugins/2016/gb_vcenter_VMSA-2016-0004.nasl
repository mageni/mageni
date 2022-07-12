###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vcenter_VMSA-2016-0004.nasl 11702 2018-10-01 07:31:38Z asteins $
#
# VMSA-2016-0004 VMware product updates address a critical security issue in the VMware Client Integration Plugin
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
  script_oid("1.3.6.1.4.1.25623.1.0.105606");
  script_cve_id("CVE-2016-2076");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11702 $");
  script_name("VMSA-2016-0004 VMware product updates address a critical security issue in the VMware Client Integration Plugin");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0004.html");

  script_tag(name:"vuldetect", value:"Check the build number");

  script_tag(name:"insight", value:"Critical VMware Client Integration Plugin incorrect session handling

The VMware Client Integration Plugin does not handle session content in a safe way. This may allow for a Man in the Middle attack or Web session hijacking in case the user of the vSphere Web Client visits a malicious Web site.");

  script_tag(name:"solution", value:"Update to 6.0U2/5.5U3d. In order to remediate the issue, both the server side and the client side (i.e. CIP of the vSphere Web Client) will need to be updated.");

  script_tag(name:"summary", value:"VMware vCenter Server updates address a critical security issue.");

  script_tag(name:"affected", value:"vCenter Server 6.0 prior to 6.0 U2 and vCenter Server 5.5 U3a, U3b, U3c");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-01 09:31:38 +0200 (Mon, 01 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-15 18:13:05 +0200 (Fri, 15 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_detect.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");

 exit(0);

}
include("vmware_esx.inc");
include("version_func.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version") ) exit( 0 );
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build") ) exit( 0 );

if( vcenter_version == "6.0.0" )
  if ( int( vcenter_build ) < int( 3634788 ) ) fix = '3634788 (6.0U2)';

if( vcenter_version == "5.5.0" )
  # Affected 5.5 U3a-U3c. 5.5 U3a Build is 3154313. 5.5 U3d Build is 3730491.
  if( version_in_range( version:vcenter_build, test_version:"3142196", test_version2:"3730490" ) ) fix = '3730491 (5.5U3d)';

if( fix )
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build:fix, typ:'vCenter' ) );
  exit(0);
}

exit(99);

