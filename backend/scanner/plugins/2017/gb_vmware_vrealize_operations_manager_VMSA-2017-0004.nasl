###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_operations_manager_VMSA-2017-0004.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# VMSA-201-0004: vRealize Operations (vROps) Remote Code Execution Vulnerability Via Apache Struts 2
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

CPE = 'cpe:/a:vmware:vrealize_operations_manager';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140229");
  script_cve_id("CVE-2017-5638");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");
  script_name("VMSA-201-0004: vRealize Operations (vROps) Remote Code Execution Vulnerability Via Apache Struts 2");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2017-0004.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Updates are available");

  script_tag(name:"summary", value:"VMware product updates resolve remote code execution vulnerability via Apache Struts 2");
  script_tag(name:"insight", value:"Multiple VMware products contain a remote code execution vulnerability due to the use of Apache Struts 2. Successful exploitation of this issue may result in the complete compromise of an affected product.");

  script_tag(name:"affected", value:"vROps 6.2.1, 6.3, 6.4 and 6.5");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-31 10:25:48 +0200 (Fri, 31 Mar 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vrealize_operations_manager_web_detect.nasl");
  script_mandatory_keys("vmware/vrealize/operations_manager/version", "vmware/vrealize/operations_manager/build");

 exit(0);

}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ! build = get_kb_item( "vmware/vrealize/operations_manager/build" ) ) exit( 0 );

if( version =~ "^6\.3\.0" )
  if( int( build ) < int( 5263486 ) ) fix = '6.3.0 Build 5263486';

if( version =~ "^6\.2\.1" )
  if( int( build ) < int( 5263486 ) ) fix = '6.2.1 Build 5263486';

if( version =~ "^6\.4\.0" )
  if( int( build ) < int( 5263486 ) ) fix = '6.4.0 Build 5263486';

if( version =~ "^6\.5\.0" )
  if( int( build ) < int( 5263486 ) ) fix = '6.5.0 Build 5263486';


if( fix )
{
  report = report_fixed_ver( installed_version:version + ' Build ' + build, fixed_version:fix );
  security_message( port:port, data:report );
  exit(0);
}

exit( 99 );

