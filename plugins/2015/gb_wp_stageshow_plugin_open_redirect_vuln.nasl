###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_stageshow_plugin_open_redirect_vuln.nasl 11994 2018-10-19 16:13:16Z cfischer $
#
# Wordpress StageShow Plugin Open Redirect Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805901");
  script_version("$Revision: 11994 $");
  script_cve_id("CVE-2015-5461");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 18:13:16 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-07 13:33:29 +0530 (Tue, 07 Jul 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Wordpress StageShow Plugin Open Redirect Vulnerability");

  script_tag(name:"summary", value:"The host is installed with wordpress
  stageshow plugin and is prone to open-redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it redirects to the malicious websites.");

  script_tag(name:"insight", value:"The error exists as the application does
  not validate the 'url' parameter upon submission to the stageshow_redirect.php
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing.");

  script_tag(name:"affected", value:"Wordpress StageShow Plugin version 5.0.8
  and probably prior.");

  script_tag(name:"solution", value:"Upgrade to Wordpress StageShow Plugin
  version 5.0.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jul/27");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/stageshow/changelog");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/07/06/2");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + "/wp-content/plugins/stageshow/stageshow_redirect.php?url=http://www.example.com";

if(http_vuln_check(port:http_port, url:url, pattern:"HTTP/1.. 301",
                   extra_check:"Location: http://www.example.com"))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port,data:report);
  exit(0);
}
