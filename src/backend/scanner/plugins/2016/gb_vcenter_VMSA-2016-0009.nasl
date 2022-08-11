###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vcenter_VMSA-2016-0009.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# VMSA-2016-0009 VMware vCenter Server updates address an important reflective cross-site scripting issue
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
  script_oid("1.3.6.1.4.1.25623.1.0.105764");
  script_cve_id("CVE-2015-6931");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 14181 $");
  script_name("VMSA-2016-0009: VMware vCenter Server updates address an important reflective cross-site scripting issue");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0009.html");

  script_tag(name:"vuldetect", value:"Check the build number");

  script_tag(name:"insight", value:"The vSphere Web Client contains a reflected cross-site scripting vulnerability due to a lack of input sanitization. An attacker can
  exploit this issue by tricking a victim into clicking a malicious link.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"VMware vCenter Server updates address an important refelctive cross-site scripting issue.");

  script_tag(name:"affected", value:"vCenter Server 5.5 prior to 5.5 update 2d

  vCenter Server 5.1 prior to 5.1 update 3d

  vCenter Server 5.0 prior to 5.0 update 3g");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-06-15 12:04:27 +0200 (Wed, 15 Jun 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_detect.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");

 exit(0);

}
include("vmware_esx.inc");
include("version_func.inc");
include("host_details.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version") ) exit( 0 );
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build") ) exit( 0 );

if( vcenter_version == "5.0.0" )
  if ( int( vcenter_build ) < int( 3891026 ) ) fix = '5.0 U3g';

if( vcenter_version == "5.1.0" )
  if ( int( vcenter_build ) < int( 3814779 ) ) fix = '5.1 U3d';

if( vcenter_version == "5.5.0" )
  if ( int( vcenter_build ) < int( 2442328 ) ) fix = '5.5 U2d';

if( fix )
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build:fix, typ:'vCenter' ) );
  exit(0);
}

exit(99);