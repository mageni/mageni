###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vcenter_VMSA-2017-0004.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# VMSA-2017-0004: VMware product updates resolve remote code execution vulnerability via Apache Struts 2
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140190");
  script_cve_id("CVE-2017-5638");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11863 $");
  script_name("VMSA-2017-0004: VMware product updates resolve remote code execution vulnerability via Apache Struts 2");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2017-0004.html");

  script_tag(name:"vuldetect", value:"Check the build number");

  script_tag(name:"insight", value:"Remote code execution vulnerability via Apache Struts 2
Multiple VMware products contain a remote code execution vulnerability due to the use of Apache Struts 2. Successful exploitation of this issue may result in the complete compromise of an affected product.");

  script_tag(name:"solution", value:"See vendor advisory for a solution.");

  script_tag(name:"summary", value:"VMware product updates resolve remote code execution vulnerability via Apache Struts 2");

  script_tag(name:"affected", value:"vCenter 6.5 and 6.0");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-16 09:26:49 +0100 (Thu, 16 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_detect.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");

 exit(0);

}
include("vmware_esx.inc");
include("version_func.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version") ) exit( 0 );
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build") ) exit( 0 );

if( vcenter_version == "6.0.0" )
  if ( int( vcenter_build ) <= int( 5112506 ) ) fix = 'See advisory.';

if( vcenter_version == "6.5.0" )
  if ( int( vcenter_build ) < int( 5178943 ) ) fix = '6.5.0b';

if( fix )
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build:fix, typ:'vCenter' ) );
  exit(0);
}

exit(99);

