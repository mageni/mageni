###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_huawei-sa-20180328-01-authentication.nasl 14156 2019-03-13 14:38:13Z cfischer $
#
# Huawei Switches Improper Authorization Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112259");
  script_version("$Revision: 14156 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 15:38:13 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-04-24 11:11:11 +0200 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-15327");

  script_name("Huawei Switches Improper Authorization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_huawei_switch_detect.nasl");
  script_mandatory_keys("huawei_switch/detected", "huawei_switch/model", "huawei_switch/version");

  script_tag(name:"summary", value:"There is an improper authorization vulnerability on Huawei switch products.
  The system incorrectly performs an authorization check when a normal user attempts to access certain information which is supposed to be accessed only by authenticated user.");
  script_tag(name:"vuldetect", value:"The script checks if the target host is an affected product that has a vulnerable firmware version installed.");
  script_tag(name:"impact", value:"Successful exploit could cause information disclosure.");
  script_tag(name:"affected", value:"Following Huawei Switch models and firmware versions are affected:

  Huawei Switch S12700 versions: V200R005C00, V200R006C00, V200R006C01, V200R007C00, V200R007C01, V200R007C20, V200R008C00, V200R008C06, V200R009C00, V200R010C00

  Huawei Switch S7700 versions: V200R001C00, V200R001C01, V200R002C00, V200R003C00, V200R005C00, V200R006C00, V200R006C01, V200R007C00, V200R007C01, V200R008C00, V200R008C06, V200R009C00, V200R010C00

  Huawei Switch S9700 versions: V200R001C00, V200R001C01, V200R002C00, V200R003C00, V200R005C00, V200R006C00, V200R006C01, V200R007C00, V200R007C01, V200R008C00, V200R009C00, V200R010C00");
  script_tag(name:"solution", value:"Update the software according to your product:

  Huawei Campus Switch S12700/S7700/S9700 fixed version: V200R010SPH002");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180328-01-authentication-en");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );
include( "revisions-lib.inc" );

if( ! model = get_kb_item( "huawei_switch/model" ) ) exit( 0 );
if( ! version = get_kb_item( "huawei_switch/version" ) ) exit( 0 );

if( model =~ "^S(127[0-9]{2}|77[0-9]{2}|97[0-9]{2})" && revcomp( a: version, b: "v200r010sph002" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V200R010SPH002" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
