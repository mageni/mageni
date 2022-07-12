###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_operations_manager_VMSA-2016-0016.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# VMSA-2016-0016: vRealize Operations (vROps) Privilege Escalation Vulnerability
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

CPE = 'cpe:/a:vmware:vrealize_operations_manager';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140064");
  script_cve_id("CVE-2016-7457");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_version("$Revision: 12096 $");
  script_name("VMSA-2016-0016: vRealize Operations (vROps) Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0016.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Updates are available");

  script_tag(name:"summary", value:"vRealize Operations (vROps) updates address privilege escalation vulnerability.");
  script_tag(name:"insight", value:"vROps contains a privilege escalation vulnerability. Exploitation of this issue may allow a vROps user who has been assigned a low-privileged role to gain full access over the application. In addition it may be possible to stop and delete Virtual Machines managed by vCenter.");

  script_tag(name:"affected", value:"vRealize Operations 6.x");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-16 15:54:11 +0100 (Wed, 16 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
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
  if( int( build ) < int( 4443153 ) ) fix = '6.3.0 Build 4443153';

if( version =~ "^6\.2\.1" )
  if( int( build ) < int( 4418887 ) ) fix = '6.2.1 Build 4418887';

if( version =~ "^6\.2\.0" )
  if( int( build ) < int( 4419192 ) ) fix = '6.2.0 Build 4419192';

if( version =~ "^6\.1\.0" )
  if( int( build ) < int( 4422776 ) ) fix = '6.1.0 Build 4422776';


if( fix )
{
  report = report_fixed_ver( installed_version:version + ' Build ' + build, fixed_version:fix );
  security_message( port:port, data:report );
  exit(0);
}

exit( 99 );

