###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zimbra_zcs_xss_vuln_mar18.nasl 12026 2018-10-23 08:22:54Z mmartin $
#
# Zimbra ZCS < 8.7.11 Patch 1 XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.112249");
  script_version("$Revision: 12026 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:22:54 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-03-29 13:30:55 +0100 (Thu, 29 Mar 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-6882");

  script_name("Zimbra ZCS < 8.7.11 Patch 1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zimbra_admin_console_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zimbra_web/installed");

  script_tag(name:"summary", value:"XSS Vulnerability in Zimbra Collaboration Suite (ZCS) before 8.7.11 Patch 1 and 8.8.x before 8.8.7.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A cross-site scripting (XSS) vulnerability in the ZmMailMsgView.getAttachmentLinkHtml function
  might allow remote attackers to inject arbitrary web script or HTML via a Content-Location header in an email attachment.");
  script_tag(name:"affected", value:"ZCS before 8.7.11 Patch 1 and 8.8.x before 8.8.7.");
  script_tag(name:"solution", value:"Update to ZCS 8.7.11 Patch 1 or 8.8.7.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Mar/52");
  script_xref(name:"URL", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");

  exit(0);
}

CPE = "cpe:/a:zimbra:zimbra_collaboration_suite";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "8.7.11" ) ) {
  vuln = TRUE;
  fix = "8.7.11 Patch 1";
}

if( version_in_range( version: version, test_version: "8.8.0", test_version2: "8.8.6" ) ) {
  vuln = TRUE;
  fix = "8.8.7";
}

if( vuln ) {
  report = report_fixed_ver( installed_version: version, fixed_version: fix );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
