###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpressmu_mult_vuln_jul09.nasl 12908 2018-12-28 23:07:11Z cfischer $
#
# WordPress / WordPress MU Multiple Vulnerabilities - July09
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800662");
  script_version("$Revision: 12908 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-29 00:07:11 +0100 (Sat, 29 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2432", "CVE-2009-2336", "CVE-2009-2335", "CVE-2009-2334");
  script_bugtraq_id(35581, 35584);
  script_name("WordPress / WordPress MU Multiple Vulnerabilities - July09");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1833");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jul/1022528.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504795/100/0/threaded");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to view the content of plugins
  configuration pages, inject malicious scripting code, or gain knowledge of sensitive username information.");

  script_tag(name:"affected", value:"WordPress / WordPress MU version prior to 2.8.1.");

  script_tag(name:"insight", value:"- Error in 'wp-settings.php' which may disclose sensitive information via
  a direct request.

  - Error occur when user attempt for failed login or password request depending
  on whether the user account exists, and it can be exploited by enumerate valid usernames.

  - Error in wp-admin/admin.php is does not require administrative authentication
  to access the configuration of a plugin, which allows attackers to specify a
  configuration file in the page parameter via collapsing-archives/options.txt,
  related-ways-to-take-action/options.php, wp-security-scan/securityscan.php,
  akismet/readme.txt and wp-ids/ids-admin.php.");

  script_tag(name:"solution", value:"Update to Version 2.8.1 or later.");

  script_tag(name:"summary", value:"The host is running WordPress / WordPress MU and is prone to multiple
  vulnerabilities");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:wordpress:wordpress_mu", "cpe:/a:wordpress:wordpress" );

if( ! infos = get_all_app_ports_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe  = infos['cpe'];
port = infos['port'];

if( ! dir = get_app_location( cpe:cpe, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/wp-settings.php";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );
if( "ABSPATHwp-include" >< res && "include_path" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );