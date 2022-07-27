###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_admanager_plus_url_redirect_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# ManageEngine AD Manager Plus URL Redirection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113106");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-08 11:30:00 +0100 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-17552");

  script_name("ManageEngine AD Manager Plus URL Redirection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_admanager_plus_detection.nasl");
  script_mandatory_keys("manageengine/admanager_plus/installed");

  script_tag(name:"summary", value:"ManageEngine AD Manager Plus is prone to a URL redirection attack.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An attacker can perform a URL redirection attack via a specially crafted URL, specifically via the src parameter.");
  script_tag(name:"impact", value:"Successful exploitation may result in a bypass of CSRF protection or potentially masquerading a malicious URL as trusted.");
  script_tag(name:"affected", value:"ManageEngine AD Manager Plus through build 6613");
  script_tag(name:"solution", value:"Update to version 6.6.20 or later.");

  script_xref(name:"URL", value:"https://umbrielsecurity.wordpress.com/2018/01/31/dangerous-url-redirection-and-csrf-in-zoho-manageengine-ad-manager-plus-cve-2017-17552/");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/ad-manager/release-notes.html");

  exit(0);
}

CPE = "cpe:/a:manageengine:admanager_plus";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );

if( !infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos['version'];
path = infos['location'];

if( version_is_less_equal( version: version, test_version: "6.6.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.6.20", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
