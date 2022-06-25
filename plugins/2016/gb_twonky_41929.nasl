###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twonky_41929.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Twonky Server Cross Site Scripting and HTML Injection Vulnerabilities
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:twonky:twonky_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108004");
  script_version("$Revision: 12313 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-27 12:00:00 +0200 (Tue, 27 Sep 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_bugtraq_id(41929);
  script_name("Twonky Server Cross Site Scripting and HTML Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_twonky_server_detect.nasl");
  script_require_ports("Services/www", 9000);
  script_mandatory_keys("twonky_server/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41929");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507616");

  script_tag(name:"summary", value:"Twonky Server is prone to a cross-site scripting vulnerability and multiple
  HTML-injection vulnerabilities because it fails to properly sanitize user-supplied input before using it in
  dynamically generated content.");

  script_tag(name:"impact", value:"Attacker-supplied HTML and script code could run in the context of the affected
  browser, potentially allowing the attacker to steal cookie-based authentication credentials or to control how the
  site is rendered to the user. Other attacks are also possible.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Versions prior to Twonky Server 4.4.18, 5.0.66, and 5.1 are vulnerable.");

  script_tag(name:"solution", value:"Update your Twonky Server to a not vulnerable version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"4.4.18" ) ||
    version_in_range( version:vers, test_version:"5", test_version2:"5.0.65" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.4.18/5.0.66" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
