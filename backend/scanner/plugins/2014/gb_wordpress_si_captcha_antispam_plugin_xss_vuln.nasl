###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_si_captcha_antispam_plugin_xss_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# WordPress SI CAPTCHA Anti-Spam Plugin Cross Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804816");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-5190");
  script_bugtraq_id(69011);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-08-19 18:46:50 +0530 (Tue, 19 Aug 2014)");
  script_name("WordPress SI CAPTCHA Anti-Spam Plugin Cross Site Scripting Vulnerability");


  script_tag(name:"summary", value:"This host is installed with WordPress SI CAPTCHA Anti-Spam Plugin and is prone
to cross-site scripting vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"insight", value:"Input passed to si-captcha-for-wordpress/captcha-secureimage/test/index.php
script via the URL is not validated before returning it to users.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary script
code in a user's browser session within the trust relationship between their
browser and the server.");
  script_tag(name:"affected", value:"WordPress SI CAPTCHA Anti-Spam plugin version 2.7.4");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/95104");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127723");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + "/wp-content/plugins/si-captcha-for-wordpress/captcha-secureima" +
            'ge/test/index.php/"/><script>alert(document.cookie);</script>' ;

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\);</script>",
   extra_check:">CAPTCHA PHP Requirements Test<"))
{
  security_message(http_port);
  exit(0);
}
