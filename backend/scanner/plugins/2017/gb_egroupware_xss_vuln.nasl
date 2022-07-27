###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_egroupware_xss_vuln.nasl 7392 2017-10-10 09:59:08Z asteins $
#
# EGroupware Community Edition Stored XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:egroupware:egroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112075");
  script_version("$Revision: 7392 $");
  script_cve_id("CVE-2017-14920");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-10 11:59:08 +0200 (Tue, 10 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-10 09:50:00 +0200 (Tue, 10 Oct 2017)");
  script_name("EGroupware Community Edition Stored XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_egroupware_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("egroupware/installed");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/09/28/12");
  script_xref(name:"URL", value:"https://github.com/EGroupware/egroupware/commit/0ececf8c78f1c3f9ba15465f53a682dd7d89529f");

  script_tag(name:"summary", value:"EGroupware Community Edition is prone to a stored cross-site scripting (XSS) vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow an unauthenticated remote attacker to inject JavaScript via the User-Agent HTTP header.");

  script_tag(name:"affected", value:"EGroupware Community Edition before version 16.1.20170922");

  script_tag(name:"solution", value:"If you are running the Community Edition of EGroupware, it is recommended to upgrade to EGroupware version 16.1.20170922 or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"16.1.20170922" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"16.1.20170922" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
