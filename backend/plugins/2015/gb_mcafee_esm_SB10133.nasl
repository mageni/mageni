###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_esm_SB10133.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# McAfee Enterprise Security Manager OS Command Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:mcafee:enterprise_security_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105478");
  script_version("$Revision: 12106 $");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("McAfee Enterprise Security Manager OS Command Injection Vulnerability");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10133");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This flaw is encountered if any authenticated user downloads a file with a specially crafted filename from the ESM.");
  script_tag(name:"solution", value:"Update to SIEM 9.3.2MR18, 9.4.2_MR8, 9.5.0MR7, or 9.5.1");
  script_tag(name:"summary", value:"SIEM Enterprise Security Manager (ESM) includes a function to upload and download files for use within the ESM. A carefully crafted filename, when downloaded, can cause command execution in the context of the ESM web server. The attack vector requires valid authentication to the ESM to execute.");
  script_tag(name:"affected", value:"SIEM 9.3.2MR17, 9.4.2MR7, 9.5.0MR6, and earlier");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-12-04 13:38:09 +0100 (Fri, 04 Dec 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_mcafee_esm_version.nasl");
  script_mandatory_keys("mcafee/esm/version", "mcafee/esm/mr");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

v = split( version, sep:'mr', keep:FALSE ); # Example: 9.5.0mr7

if( isnull( v[0] ) || isnull( v[1] ) ) exit( 0 );

version = v[0] + '.' + v[1]; # Example: 9.5.0.7

if( version_in_range( version:version, test_version:"9.3.2", test_version2:"9.3.2.17" ) ) fix = '9.3.2MR18 / /9.5.1';
else if( version_in_range( version:version, test_version:"9.4.2", test_version2:"9.4.2.7" ) )  fix = '9.4.2MR8 / 9.5.1';
else if( version_in_range( version:version, test_version:"9.5.0", test_version2:"9.5.0.6" ) )  fix = '9.5.0MR7 / 9.5.1';

if( fix )
{
  report = 'Installed version: ' + v[0] + 'MR' + v[1] + '\n' +
           'Fixed version:     ' + fix;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

