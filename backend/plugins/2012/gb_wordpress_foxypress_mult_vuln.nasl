###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_foxypress_mult_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# WordPress FoxyPress Plugin Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803042");
  script_version("$Revision: 11374 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-11-02 18:49:49 +0530 (Fri, 02 Nov 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress FoxyPress Plugin Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://www.waraxe.us/content-95.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51109");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22374");

  script_tag(name:"summary", value:"This host is running WordPress
  FoxyPress plugin and is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Inputs passed via the

  - 'xtStartDate', 'txtEndDate', and 'txtProductCod' parameters to edit.php,

  - 'id' parameter to foxypress-manage-emails.php,

  - 'status' and 'page' parameters to edit.php and

  - 'url' parameter to foxypress-affiliate.php are not properly sanitised
    before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary web script or HTML in a user's browser session in
  the context of an affected site, manipulate SQL queries by injecting arbitrary SQL
  code and to redirect users to arbitrary web sites and conduct phishing attacks.");

  script_tag(name:"affected", value:"WordPress FoxyPress Plugin Version 0.4.2.5
  and prior.");

  script_tag(name:"solution", value:"No known solution was made available for
  at least one year since the disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";
url = dir + "/wp-content/plugins/foxypress/dialog.htm";

if(http_vuln_check(port:port, url:url, check_header:TRUE, usecache:TRUE, pattern:'>FoxyPress Plugin<', extra_check:make_list('/foxypress/forum<','"FoxyPressDialog.insert'))){

  url = string(dir, "/wp-content/plugins/foxypress/Inventory.csv");

  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:'"Item Code"', extra_check:make_list('"Item Name",', ',"Item Category",', '"Subscription Start Date"'))){
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
