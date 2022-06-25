###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mikrotik_mult_vuln.nasl 13783 2019-02-20 11:12:24Z cfischer $
#
# MikroTik Router Multiple Vulnerabilities
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113068");
  script_version("$Revision: 13783 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 12:12:24 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-12-14 12:11:10 +0100 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2017-17538", "CVE-2017-17537");

  script_name("MikroTik Router Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"Multiple DoS vulnerabilities in MicroTik Router OS v6.40.5 and before.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerabilities allow for two ways of causing an Denial of Service:

  - An attacker can flood the device with ICMP packets

  - An attacker can connect to TCP-port 53 an send data starting with a lot of Null-Byte characters, probably
related to DNS.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to make the device
unavailable.");

  script_tag(name:"affected", value:"MikroTik Router OS v6.40.5 and before");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/current-release-tree");

  exit(0);
}

CPE = "cpe:/o:mikrotik:routeros";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE , nofork: TRUE ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "6.40.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
