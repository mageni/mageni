###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_operations_manager_VMSA-2016-0020.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# VMSA-2016-0020: vRealize Operations REST API Deserialization Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.140063");
  script_cve_id("CVE-2016-7462");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_version("$Revision: 11961 $");
  script_name("VMSA-2016-0020: vRealize Operations REST API Deserialization Vulnerability");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0020.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to 6.4.0 or later");

  script_tag(name:"summary", value:"vRealize Operations update addresses REST API deserialization vulnerability.");
  script_tag(name:"insight", value:"vRealize Operations contains a deserialization vulnerability in its REST API implementation. This issue may result in a Denial of Service as it allows for writing of files with arbitrary content and moving existing files into certain folders. The name format of the destination files is predefined and their names cannot be chosen. Overwriting files is not feasible.");

  script_tag(name:"affected", value:"vRealize Operations 6.x < 6.4.0");

  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-16 15:53:11 +0100 (Wed, 16 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vrealize_operations_manager_web_detect.nasl");
  script_mandatory_keys("vmware/vrealize/operations_manager/version");

 exit(0);

}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version =~ "^6\." )
  if( version_is_less( version:version, test_version:"6.4.0" ) ) fix = '6.4.0';

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:port, data:report );
  exit(0);
}

exit( 99 );

