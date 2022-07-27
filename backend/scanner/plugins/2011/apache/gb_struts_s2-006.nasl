# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801940");
  script_version("2021-04-01T07:54:37+0000");
  script_cve_id("CVE-2011-1772", "CVE-2011-2088");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-01 10:13:05 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_name("Apache Struts/XWork Multiple Vulnerabilities (S2-006)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/struts/http/detected");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-006");
  script_xref(name:"URL", value:"http://www.ventuneac.net/security-advisories/MVSA-11-006");
  script_xref(name:"Advisory-ID", value:"S2-006");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the
  response.");

  script_tag(name:"insight", value:"The flaw is due to error in XWork, when handling the
  's:submit' element and a nonexistent method, which gives sensitive information about
  internal Java class paths.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain
  potentially sensitive information about internal Java class paths via vectors involving
  an s:submit element and a nonexistent method.");

  script_tag(name:"affected", value:"XWork version 2.2.1 in Apache Struts 2.2.1 is known
  to be vulnerable.");

  script_tag(name:"solution", value:"Update Apache Struts to version 2.2.3 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/Nonmethod.action";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

if("Stacktraces" >< res && "Nonmethod" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);