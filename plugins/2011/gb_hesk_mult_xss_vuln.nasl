##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hesk_mult_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# HESK Multiple Cross-site Scripting (XSS) Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802132");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-5287");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("HESK Multiple Cross-site Scripting (XSS) Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519148");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/multiple_xss_in_hesk.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103733/hesk-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaws are due to improper validation of

  - input passed via the 'hesk_settings[tmp_title]' and 'hesklang[ENCODING]'
    parameters to '/inc/header.inc.php'.

  - input passed via 'hesklang[attempt]' parameter to various files in '/inc/'
    directory.

  - input appended to the URL after '/language/en/text.php', before being
  returned to the user.");
  script_tag(name:"solution", value:"Upgrade to HESK version 2.3 or later.");
  script_tag(name:"summary", value:"This host is running HESK and is prone to multiple cross-site
  scripting vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of affected website.");
  script_tag(name:"affected", value:"HESK version 2.2 and prior.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.hesk.com/");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

hsPort = get_http_port(default:80);

if(!can_host_php(port:hsPort)){
  exit(0);
}

foreach dir (make_list_unique("/hesk", "/Hesk", "/", cgi_dirs(port:hsPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:hsPort);

  if('>Powered by <' >< rcvRes && '> HESK&' >< rcvRes)
  {
    url = string(dir, '/inc/header.inc.php?hesklang[ENCODING]="><script>' +
                      "alert('OpenVAS-XSS');</script>");

    if(http_vuln_check(port:hsPort, url:url, pattern:"><script>alert" +
                          "\('OpenVAS-XSS'\);</script>", check_header:TRUE))
    {
      security_message(port:hsPort);
      exit(0);
    }
  }
}

exit(99);
