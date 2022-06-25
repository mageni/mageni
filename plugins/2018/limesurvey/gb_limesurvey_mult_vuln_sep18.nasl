###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limesurvey_mult_vuln_sep18.nasl 13093 2019-01-16 10:15:31Z ckuersteiner $
#
# LimeSurvey <= 3.14.3 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.113264");
  script_version("$Revision: 13093 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-16 11:15:31 +0100 (Wed, 16 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-09-07 10:11:44 +0200 (Fri, 07 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-1000658", "CVE-2018-1000659");

  script_name("LimeSurvey <= 3.14.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/installed");

  script_tag(name:"summary", value:"LimeSurvey is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - An authenticated user uploading a zip archive containing malicious php files can result
    in the attacker gaining code execution via webshell.

  - An authenticated user uploading a specially crafted zip file can result
    in the attacker gaining remote code execution.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain complete control over
the target system.");

  script_tag(name:"affected", value:"LimeSurvey through version 3.14.3.");

  script_tag(name:"solution", value:"Update to version 3.14.4.");

  script_xref(name:"URL", value:"https://vuldb.com/?id.123646");
  script_xref(name:"URL", value:"https://vuldb.com/?id.123647");
  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/commit/72a02ebaaf95a80e26127ee7ee2b123cccce05a7");
  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/commit/20fc85edccc80e7e7f162613542792380c44446a");
  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/commit/91d143230eb357260a19c8424b3005deb49a47f7");

  exit(0);
}

CPE = "cpe:/a:limesurvey:limesurvey";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.14.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.14.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
