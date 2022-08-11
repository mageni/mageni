# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:finalwire:aida64";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107635");
  script_version("2019-04-06T07:21:05+0000");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-06 07:21:05 +0000 (Sat, 06 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-05 15:15:05 +0200 (Fri, 05 Apr 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("AIDA64 <= 5.99.4900 SEH Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"This host is running AIDA64 and is prone to
  an buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By sending specially crafted data to the 'Display name' and
  'Load from file' fields a buffer overflow might occur.");

  script_tag(name:"impact", value:"A local attacker could overflow a buffer and execute arbitrary code on the system.");

  script_tag(name:"affected", value:"AIDA64 Editions through version 5.99.4900.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"solution", value:"No known solution is available as of 05th April, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46636");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46639");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_finalwire_aida64_detect_win.nasl");
  script_mandatory_keys("finalwire/aida64/win/detected");
  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"5.99.4900" ) )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}
exit( 99 );
