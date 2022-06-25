###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybb_xss_vuln_aug18.nasl 12343 2018-11-14 02:59:57Z ckuersteiner $
#
# myBB <= 1.8.17 XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113261");
  script_version("$Revision: 12343 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-14 03:59:57 +0100 (Wed, 14 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-08-31 12:56:57 +0200 (Fri, 31 Aug 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-15596");

  script_name("myBB <= 1.8.17 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"summary", value:"myBB is prone to a Cross-Site-Scripting (XSS) Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The thread titles are not sanitized, resulting in XSS.");
  script_tag(name:"impact", value:"Successful authentication would allow an authenticated attacker
  to inject arbitrary code into the website.");
  script_tag(name:"affected", value:"mybb through version 1.8.17.");
  script_tag(name:"solution", value:"Update to version 1.8.18");

  script_xref(name:"URL", value:"https://blog.mybb.com/2018/08/22/mybb-1-8-18-released-security-maintenance-release/");

  exit(0);
}

CPE = "cpe:/a:mybb:mybb";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port, nofork: TRUE ) ) exit( 0 );

if( version_is_less( version: version, test_version: "1.8.18" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.18" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
