###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_priv_delegation_vuln_nov18.nasl 13394 2019-02-01 07:36:10Z mmartin $
#
# Samba >= 3.0.25, <= 4.5.2 Privilege Delegation Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113288");
  script_version("$Revision: 13394 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 08:36:10 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-06 14:33:00 +0200 (Tue, 06 Nov 2018)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-2125");

  script_name("Samba >= 3.0.25, <= 4.5.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to a privilege delegation vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Samba always requests forwardable tickets when using Kerberos authentication.
  A service to which Samba authenticated using Kerberos could subsequently
  use the ticket to impersonate Samba to other services or domain users.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to gain
  additional access rights.");
  script_tag(name:"affected", value:"Samba versions 3.0.25 through 4.3.12, 4.4.0 through 4.4.7 and 4.5.0 through 4.5.2.");
  script_tag(name:"solution", value:"Update to version 4.3.13, 4.4.8 or 4.5.3 respectively.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2016-2125.html");

  exit(0);
}

CPE = "cpe:/a:samba:samba";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos['version'];
insloc = infos['location'];

if( version_in_range( version: version, test_version: "3.0.25", test_version2: "4.3.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.13", install_path: insloc );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.4.0", test_version2: "4.4.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.4.8", install_path: insloc );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.5.0", test_version2: "4.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.5.3", install_path: insloc );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
