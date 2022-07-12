###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_remote_pw_reset.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT Pre-Auth Remote Password Reset Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:mantisbt:mantisbt';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108140");
  script_version("$Revision: 12818 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-04-18 08:00:00 +0200 (Tue, 18 Apr 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2017-7615");

  script_name("MantisBT Pre-Auth Remote Password Reset Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mantisbt/detected");

  script_xref(name:"URL", value:"http://hyp3rlinx.altervista.org/advisories/MANTIS-BUG-TRACKER-PRE-AUTH-REMOTE-PASSWORD-RESET.txt");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=22690");

  script_tag(name:"summary", value:"This host is installed with MantisBT which is prone to a remote password reset vulnerability.");

  script_tag(name:"insight", value:"The flaw exists because MantisBT allows arbitrary password reset and unauthenticated admin access
  via an empty confirm_hash value to verify.php.");

  script_tag(name:"vuldetect", value:"Check if it is possible to reset a admin/user password.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote unauthenticated attacker to reset a admin/user password.");

  script_tag(name:"affected", value:"MantisBT versions 1.3.x before 1.3.10 and 2.3.0.");

  script_tag(name:"solution", value:"Upgrade to MantisBT version 1.3.10, 2.3.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"https://mantisbt.org");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/verify.php?id=1&confirm_hash=";

# Used the form here as the message of the confirmation might be translated
if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:'<form id="account-update-form" method="post" action="account_update.php">' ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
