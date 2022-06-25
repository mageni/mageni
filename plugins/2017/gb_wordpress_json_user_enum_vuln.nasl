###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_json_user_enum_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# WordPress 'json' User Enumeration Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809892");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2017-5487");
  script_bugtraq_id(95391);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-03 17:16:53 +0530 (Fri, 03 Mar 2017)");
  script_name("WordPress 'json' User Enumeration Vulnerability");

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41497");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8715");

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to user enumeration vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  the response.");

  script_tag(name:"insight", value:"The flaw exists due to
  'wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php' in the
  REST API implementation in WordPress 4.7 before 4.7.1 does not properly
  restrict listings of post authorsimproper access restriction to some
  sensitive pages.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attacker to obtain sensitive information.");

  script_tag(name:"affected", value:"WordPress versions 4.7 and earlier on Windows.");

  script_tag(name:"solution", value:"Upgrade to WordPress version 4.7.1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  # This NVT produces to much false positive....
  script_tag(name:"deprecated", value:TRUE);

  script_xref(name:"URL", value:"https://wordpress.org");
  exit(0);
}

exit(66);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");


if(!http_port = get_app_port(cpe:CPE)){
 exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/wp-json/wp/v2/users/';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
  pattern:'"id":', extra_check:make_list('"name":', '"url":', '"description":', '"link":')))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
