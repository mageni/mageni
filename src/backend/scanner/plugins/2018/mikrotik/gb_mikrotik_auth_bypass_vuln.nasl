###############################################################################
# OpenVAS Vulnerability Test
#
# MikroTik RouterOS 6.41.4 Authentication Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113156");
  script_version("2019-04-18T07:49:40+0000");
  script_tag(name:"last_modification", value:"2019-04-18 07:49:40 +0000 (Thu, 18 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-04-17 13:17:37 +0200 (Tue, 17 Apr 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-10066");

  script_name("MikroTik RouterOS 6.41.4 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"An issue was discovered in MikroTik RouterOS.
  Missing OpenVPN server certificate verification allows a remote unauthenticated attacker capable of intercepting
client traffic to act as a malicious OpenVPN server.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to gain access to the target
host's internal network.");

  script_tag(name:"affected", value:"MikroTik RouterOS through version 6.41.4");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://janis-streib.de/2018/04/11/mikrotik-openvpn-security/");
  script_xref(name:"URL", value:"https://mikrotik.com/download");

  exit(0);
}

CPE = "cpe:/o:mikrotik:routeros";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "6.41.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
