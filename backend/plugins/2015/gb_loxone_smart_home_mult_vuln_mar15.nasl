###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_loxone_smart_home_mult_vuln_mar15.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# Loxone Smart Home Multiple Vulnerabilities - Mar15
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

CPE = 'cpe:/a:loxone:loxone';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805298");
  script_version("$Revision: 11975 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-10 09:36:22 +0530 (Tue, 10 Mar 2015)");
  script_name("Loxone Smart Home Multiple Vulnerabilities - Mar15");

  script_tag(name:"summary", value:"This host is installed with Loxone Smart
  Home and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - the device transmitting all data in cleartext.

  - HTTP requests do not require multiple steps, explicit confirmation, or a
  unique token when performing certain sensitive actions.

  - the '/dev/cfg/version' script does not validate input appended to the
  response header before returning it to the user.

  - the '/dev/sps/io/' script does not validate input passed via the URL before
  returning it to users.

  - the '/dev/sps/addcmd/' script does not validate input to the description field
  in a new task before returning it to users.

  - the program storing user credentials in an insecure manner.

  - improper restriction of JavaScript from one web page from accessing another
  when the pages originate from different domains.

  - an unspecified error related to malformed HTTP requests or using the
  synflood metasploit module.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to conduct man-in-the-middle attack, cross-site request
  forgery attack, cross-frame scripting (XFS) attack, denial-of-service (DoS)
  attack, decrypt user credentials, insert additional arbitrary HTTP headers
  and execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"Loxone Smart Home version 5.49");

  script_tag(name:"solution", value:"Upgrade to Loxone Smart Home version 6.3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130577");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_loxone_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("loxone/web/detected");
  script_xref(name:"URL", value:"http://www.loxone.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if ( !http_port = get_app_port(cpe:CPE, service:'www' )) exit (0);

url = "/dev/cfg/version%0D%0A%0D%0A<html><script>alert(document.cookie)" +
      "</script></html>";
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\)</script>",
   extra_check:">Loxone Miniserver error<"))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);
