###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twonky_server_mult_vuln.nasl 12356 2018-11-15 06:27:24Z ckuersteiner $
#
# Twonky Server < 8.5.1 Multiple Vulnerabilities (Version Check)
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
  script_oid("1.3.6.1.4.1.25623.1.0.113148");
  script_version("$Revision: 12356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 07:27:24 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-04-03 14:36:00 +0200 (Tue, 03 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-7171", "CVE-2018-7203");

  script_name("Twonky Server < 8.5.1 Multiple Vulnerabilities (Version Check)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_twonky_server_detect.nasl");
  script_mandatory_keys("twonky_server/installed");

  script_tag(name:"summary", value:"Twonky Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target system.");

  script_tag(name:"insight", value:"Following vulnerabilities exist:

  Directory traversal vulnerability in Twonky Server allows remote attackers to share the contents of arbitrary directories
  via a .. (dot dot) in the contentbase parameter to rpc/set_all.

  Cross-site scripting (XSS) vulnerability in Twonky Server allows remote attackers to inject arbitrary web script or HTML
  via the friendlyname parameter to rpc/set_all.");

  script_tag(name:"affected", value:"Twonky Server versions 7.0.11 through 8.5.");

  script_tag(name:"solution", value:"Update to version 8.5.1 or later.

  As a workaround set a strong password for the WebGUI which blocks access to the affected RCP calls.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/146938/TwonkyMedia-Server-7.0.11-8.5-Directory-Traversal.html");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/146939/TwonkyMedia-Server-7.0.11-8.5-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"https://github.com/mechanico/sharingIsCaring/blob/master/twonky.py");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44350/");
  script_xref(name:"URL", value:"http://docs.twonky.com/display/TRN/Twonky+Server+8.5.1");

  exit(0);
}

CPE = "cpe:/a:twonky:twonky_server";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "7.0.11", test_version2: "8.5.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.5.1" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
