###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortios_undocumented_interactive_login_ulnerability_version.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# FortiOS: SSH Undocumented Interactive Login Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105507");
  script_tag(name:"cvss_base", value:"10.0");
  script_cve_id("CVE-2016-1909");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12363 $");

  script_name("FortiOS: SSH Undocumented Interactive Login Vulnerability");

  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-16-001");

  script_tag(name:"impact", value:"Remote console access to vulnerable devices with 'Administrative Access' enabled for SSH.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"FortiOS branch 4.3: Upgrade to FortiOS 4.3.17 or later

FortiOS branch 5.0: Upgrade to FortiOS 5.0.8 or later");

  script_tag(name:"summary", value:"FortiOS Undocumented Interactive Login Vulnerability");

  script_tag(name:"affected", value:"FortiOS 4.3.0 to 4.3.16

FortiOS 5.0.0 to 5.0.7");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-01-13 11:43:18 +0100 (Wed, 13 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("forti/FortiOS/version");

  exit(0);
}

include("version_func.inc");

if( ! version = get_kb_item( "forti/FortiOS/version" )) exit( 0 );

if( version_in_range( version:version, test_version:"4.3", test_version2:"4.3.16" ) ) fix = '4.3.17';
if( version_in_range( version:version, test_version:"5.0", test_version2:"5.0.7" ) )  fix = '5.0.8';

if( fix )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     ' + fix;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
