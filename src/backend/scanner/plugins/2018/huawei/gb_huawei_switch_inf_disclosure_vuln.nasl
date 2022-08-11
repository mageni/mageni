###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_huawei_switch_inf_disclosure_vuln.nasl 12045 2018-10-24 06:51:17Z mmartin $
#
# Huawei Switches Information Disclosure Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113083");
  script_version("$Revision: 12045 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 08:51:17 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-12 14:44:44 +0100 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-5394");

  script_name("Huawei Switches Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_huawei_switch_detect.nasl");
  script_mandatory_keys("huawei_switch/detected", "huawei_switch/model", "huawei_switch/version");

  script_tag(name:"summary", value:"Multiple Huawei Campus switches allow remote attackers to enumerate usernames via vectors involving use of SSH by the maintenance terminal.");
  script_tag(name:"vuldetect", value:"The script checks if the target host is an affected product that has a vulnerable firmware version installed.");
  script_tag(name:"affected", value:"Following Huawei Switch models and firmware versions are affected:

  Huawei Campus Switch S9300/S9300E/S7700/S9700 versions: V200R001C00SPC300, V200R002C00SPC300, V200R003C00SPC500

  Huawei Campus Switch S5700/S6700/S5300/S6300 versions: V200R001C00SPC300, V200R002C00SPC300, V200R003C00SPC300

  Huawei Campus Switch S2300/S2700/S3300/S3700 versions: V100R006C05");
  script_tag(name:"solution", value:"Update the software according to your product:

  Huawei Campus Switch S9300/S9300E/S7700/S9700 fixed version: V200R005C00SPC300

  Huawei Campus Switch S5700/S6700/S5300/S6300 fixed version: V200R005C00SPC300

  Huawei Campus Switch S2300/S2700/S3300/S3700 fixed version: V100R006SPH018");

  script_xref(name:"URL", value:"http://www.huawei.com/us/psirt/security-advisories/2014/hw-362701");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/97763");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );
include( "revisions-lib.inc" );

if( ! model = get_kb_item( "huawei_switch/model" ) ) exit( 0 );
if( ! version = get_kb_item( "huawei_switch/version" ) ) exit( 0 );

if( model =~ "^S(93[0-9]{2}|93[0-9]{2}E|77[0-9]{2}|97[0-9]{2}|57[0-9]{2}|67[0-9]{2}|53[0-9]{2}|63[0-9]{2})"  && revcomp( a: version, b: "v200r005c00spc300" ) < 0) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V200R005C00SPC300" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ "^S(23[0-9]{2}|27[0-9]{2}|33[0-9]{2}|37[0-9]{2})" && revcomp( a: version, b: "v100r006sph018" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V100R006SPH018" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
