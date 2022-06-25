###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mahara_mult_vuln.nasl 12026 2018-10-23 08:22:54Z mmartin $
#
# Mahara <17.04.8, <17.10.5, <18.04.1 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.112290");
  script_version("$Revision: 12026 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:22:54 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-04 10:26:06 +0200 (Mon, 04 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11195", "CVE-2018-11196");

  script_name("Mahara <17.04.8, <17.10.5, <18.04.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
  script_mandatory_keys("mahara/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"This host is running Mahara and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mahara is prone to the following vulnerabilities:

  - Mahara is vulnerable to the browser 'back and refresh' attack. This allows malicious users with physical access to the web browser of a Mahara user,
  after they have logged in, to potentially gain access to their Mahara credentials. (CVE-2018-11195)

  - Mahara can be used as medium to transmit viruses by placing infected files into a Leap2A archive and uploading that to Mahara.
  In contrast to other ZIP files that are uploaded, ClamAV (when activated) does not check Leap2A archives for viruses, allowing malicious files to be available for download.
  While files cannot be executed on Mahara itself, Mahara can be used to transfer such files to user computers. (CVE-2018-11196)");
  script_tag(name:"affected", value:"Mahara 17.04 before 17.04.8 and 17.10 before 17.10.5 and 18.04 before 18.04.1");
  script_tag(name:"solution", value:"Update to Mahara 17.04.8, 17.10.5 or 18.04.1 respectively.");

  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1770561");
  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=8269");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1770535");
  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=8270");

  exit(0);
}

CPE = "cpe:/a:mahara:mahara";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_equal( version: version, test_version: "18.04" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "18.04.1" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "17.04", test_version2: "17.04.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "17.04.8" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "17.10", test_version2: "17.10.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "17.10.5" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
