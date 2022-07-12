###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mikrotik_dos_vuln.nasl 12026 2018-10-23 08:22:54Z mmartin $
#
# MikroTik RouterOS 6.41.4 Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113161");
  script_version("$Revision: 12026 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:22:54 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-19 12:37:00 +0200 (Thu, 19 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-10070");

  script_name("MikroTik RouterOS 6.41.4 Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik is prone to a Denial of Service vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if the target is a vulnerable device running a vulnerable firmware version.");
  script_tag(name:"insight", value:"A vulnerability in MikroTik Version 6.41.4 could allow an unauthenticated remote attacker
  to exhaust all available CPU and all available RAM by sending a crafted FTP request on port 21 that begins with many '\0' characters,
  preventing the affected router from accepting new FTP connections. The router will reboot after 10 minutes,
  logging a 'router was rebooted without proper shutdown' message.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to effectively block access to the target host
  for an arbitrary timespan.");
  script_tag(name:"affected", value:"MikroTik RouterOS through version 6.41.4.");
  script_tag(name:"solution", value:"Update to version 6.42 or above.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/147183/MikroTik-6.41.4-Denial-Of-Service.html");
  script_xref(name:"URL", value:"https://mikrotik.com/download");

  exit(0);
}

CPE = "cpe:/o:mikrotik:routeros";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "6.41.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.42" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
