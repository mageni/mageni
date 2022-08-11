###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_infoblox_netmri_rxss_vuln.nasl 12998 2019-01-09 13:46:07Z asteins $
#
# Infoblox NetMRI 7.1.1 Reflected Cross-Site Scripting Vulnerability
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107339");
  script_version("2019-03-22T15:58:59+0000");
  script_tag(name:"last_modification", value:"2019-03-22 15:58:59 +0000 (Fri, 22 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-09-10 14:25:14 +0200 (Mon, 10 Sep 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2018-6643");

  script_name("Infoblox NetMRI 7.1.1 Reflected Cross-Site Scripting Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_netmri_detect.nasl");
  script_mandatory_keys("netMRI/detected");

  script_tag(name:"summary", value:"Infoblox NetMRI 7.1.1 is prone to a reflected Cross-Site
    Scripting vulnerability. This could allow an unauthenticated, remote attacker to conduct an attack");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient validation of user-supplied input via
the /api/docs/index.php query parameter. An attacker could exploit this vulnerability by persuading a user of the
interface to click a crafted link.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to execute arbitrary script code
in the context of the interface or allow the attacker to access sensitive browser-based information.");

  script_tag(name:"affected", value:"Infoblox NetMRI version 7.1.1. Other versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution is available as of 22nd March, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/undefinedmode/CVE-2018-6643");

  exit(0);
}

CPE = "cpe:/a:infoblox:netmri";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "7.1.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
