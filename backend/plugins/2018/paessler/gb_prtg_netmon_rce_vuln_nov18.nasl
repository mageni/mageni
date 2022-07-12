###############################################################################
# OpenVAS Vulnerability Test
#
# PRTG Network Monitor <=18.3.43.2323 Remote Code Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113299");
  script_version("2019-05-10T14:24:23+0000");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-13 15:30:47 +0200 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-19204");

  script_name("PRTG Network Monitor <=18.3.43.2323 Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_prtg_network_monitor_detect.nasl");
  script_mandatory_keys("prtg_network_monitor/installed");

  script_tag(name:"summary", value:"PRTG Network Monitor is prone to a remote command execution (RCE) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"When creating an HTTP Advanced Sensor, the users input in the POST parameter 'proxyport_'
  is mishandled. The attacker can craft an HTTP request and override the 'writeresult'
  command-line parameter for HttpAdvancedSensor.exe to store arbitrary data in
  an arbitrary place on the file system, including executables.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  gain complete control over the target system.");
  script_tag(name:"affected", value:"PRTG Network Monitor through version 18.3.43.2323.");
  script_tag(name:"solution", value:"Update to version 18.3.44.2054.");

  script_xref(name:"URL", value:"https://www.ptsecurity.com/ww-en/analytics/threatscape/pt-2018-23/");
  script_xref(name:"URL", value:"http://en.securitylab.ru/lab/PT-2018-23");

  exit(0);
}

CPE = "cpe:/a:paessler:prtg_network_monitor";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "18.3.44.2054" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "18.3.44.2054" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );