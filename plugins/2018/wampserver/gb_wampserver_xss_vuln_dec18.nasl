###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wampserver_xss_vuln_dec18.nasl 13012 2019-01-10 08:11:33Z asteins $
#
# WampServer < 3.1.5 XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.112471");
  script_version("$Revision: 13012 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-10 09:11:33 +0100 (Thu, 10 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-12-21 15:57:10 +0100 (Fri, 21 Dec 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-1000848");

  script_name("WampServer < 3.1.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wampserver_detect.nasl");
  script_mandatory_keys("wampserver/installed");

  script_tag(name:"summary", value:"WampServer is prone to an XSS vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to create a crafted link to
  inject arbitrary HTML and JavaScript into the target website.");
  script_tag(name:"affected", value:"WampServer before version 3.1.5.");
  script_tag(name:"solution", value:"Update to version 3.1.5.");

  script_xref(name:"URL", value:"http://forum.wampserver.com/read.php?2,153491");

  exit(0);
}

CPE = "cpe:/a:wampserver:wampserver";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.1.5" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.5" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
