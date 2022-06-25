###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kentico_cms_access_control_bypass_vuln.nasl 9206 2018-03-26 11:27:00Z asteins $
#
# Kentico CMS < 9.0.51 & < 10.0.48 Access Control Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.112248");
  script_version("$Revision: 9206 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-26 13:27:00 +0200 (Mon, 26 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-20 14:34:43 +0100 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-17736");

  script_name("Kentico CMS < 9.0.51 & < 10.0.48 Access Control Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kentico_cms_detect.nasl");
  script_mandatory_keys("kentico_cms/detected");

  script_tag(name:"summary", value:"Kentico CMS is prone to an access control bypass vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:'Kentico CMS is vulnerable to an access control bypass as it fails to properly
restrict access the installation wizard. It is possible for anunauthenticated user to gain access to these pages
and perform actions such as installing a new starter site or obtaining access to the "New  site wizard",
which automatically authenticates as the Global Administrator.');
  script_tag(name:"impact", value:"An unauthenticated attacker may leverage this issue to gain Global Administrator access
to a Kentico installation. From there it is possible to perform administrative actions, install news sites or potentially obtain remote code execution.");
  script_tag(name:"affected", value:"Kentico CMS versions 9 up to 9.0.51 and version 10 up to 10.0.48.");
  script_tag(name:"solution", value:"Upgrade Kentico CMS to version 9.0.51 or 10.0.48.");

  script_xref(name:"URL", value:"https://blog.hivint.com/advisory-access-control-bypass-in-kentico-cms-cve-2017-17736-49e1e43ae55b");

  exit( 0 );
}

CPE = "cpe:/a:kentico:cms";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if ( version =~ "^9\.0" ) {
  if ( version_is_less( version: version, test_version: "9.0.51" ) ) {
    vuln = TRUE;
    fix = "9.0.51";
  }
} else if ( version =~ "^10\.0" ) {
  if ( version_is_less( version: version, test_version: "10.0.48" ) ) {
    vuln = TRUE;
    fix = "10.0.48";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version: version, fixed_version: fix );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
