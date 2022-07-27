###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squirrelmail_mult_xss_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# SquirrelMail < 1.4.23 Multiple XSS Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.112348");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-06 11:31:46 +0200 (Mon, 06 Aug 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-14950", "CVE-2018-14951", "CVE-2018-14952", "CVE-2018-14953", "CVE-2018-14954", "CVE-2018-14955");

  script_name("SquirrelMail < 1.4.23 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("squirrelmail_detect.nasl");
  script_mandatory_keys("squirrelmail/installed");

  script_tag(name:"summary", value:"SquirrelMail is prone to multiple cross-site scripting (XSS) vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"SquirrelMail version up to and including 1.4.22.");
  script_tag(name:"solution", value:"Update to a upcoming version 1.4.23 or later. As an alternative apply
  the patches listed in the references.");

  script_xref(name:"URL", value:"https://github.com/hannob/squirrelpatches");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2018/07/26/2");
  script_xref(name:"URL", value:"https://bugs.debian.org/905023");
  script_xref(name:"URL", value:"https://sourceforge.net/p/squirrelmail/bugs/2831/");

  exit(0);
}

CPE = "cpe:/a:squirrelmail:squirrelmail";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "1.4.23" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.4.23" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
