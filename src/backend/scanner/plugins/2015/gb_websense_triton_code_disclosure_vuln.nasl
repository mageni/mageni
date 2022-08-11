###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_websense_triton_code_disclosure_vuln.nasl 11452 2018-09-18 11:24:16Z mmartin $
#
# Websense Triton Source Code Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:websense:triton';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106002");
  script_version("$Revision: 11452 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-06-03 10:18:34 +0700 (Wed, 03 Jun 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Websense Triton Source Code Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_websense_triton_detect.nasl");
  script_mandatory_keys("websense_triton/installed");

  script_tag(name:"summary", value:"Websense Triton is vulnerable to a source code disclosure
vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check
the response");

  script_tag(name:"insight", value:"By appending a double quote character after JSP URLs, Websense
will return the source code of the JSP instead of executing the JSP.");

  script_tag(name:"impact", value:"An attacker can use this vulnerability to inspect parts of
Websense's source code in order to gain more knowledge about Websense's internals.");

  script_tag(name:"affected", value:"Websense Triton v7.8.3 and v7.7");

  script_tag(name:"solution", value:"Install the hotfix 02 for version 7.8.4 or update to version
8.0.");

  script_xref(name:"URL", value:"https://www.securify.nl/advisory/SFY20140907/source_code_disclosure_of_websense_triton_jsp_files_via_double_quote_character.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/triton/login/pages/certificateDone.jsp%22';

if (http_vuln_check(port: port, url: url, check_header:TRUE,
                    pattern: '<%@page import="com.websense.java.eip.client.login.BBLogin"%>')) {
  report = report_vuln_url( port:port, url:url );
  security_message(port: port, data:url);
  exit(0);
}

exit(0);
