###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wampserver_xss_vuln.nasl 9149 2018-03-20 12:26:00Z jschulte $
#
# WampServer 3.1.1 XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113139");
  script_version("$Revision: 9149 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-20 13:26:00 +0100 (Tue, 20 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-20 12:40:00 +0100 (Tue, 20 Mar 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-8732");

  script_name("WampServer 3.1.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wampserver_detect.nasl");
  script_mandatory_keys("wampserver/installed");

  script_tag(name:"summary", value:"WampServer is prone to an XSS vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The XSS is possible through the virtual_del parameter.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to create a crafted link to
  inject arbitrary HTML and JavaScript into the target website.");
  script_tag(name:"affected", value:"WampServer through version 3.1.1.");
  script_tag(name:"solution", value:"Update to version 3.1.2.");

  script_xref(name:"URL", value:"http://forum.wampserver.com/read.php?2,138295,150615,page=6#msg-150615");

  exit( 0 );
}

CPE = "cpe:/a:wampserver:wampserver";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.1.2" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.2" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
