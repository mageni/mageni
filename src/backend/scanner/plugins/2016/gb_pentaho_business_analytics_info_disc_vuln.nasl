# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:hitachi:vantara_pentaho";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808208");
  script_version("2021-11-09T09:31:13+0000");
  script_tag(name:"last_modification", value:"2021-11-09 09:31:13 +0000 (Tue, 09 Nov 2021)");
  script_tag(name:"creation_date", value:"2016-05-24 10:37:42 +0530 (Tue, 24 May 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2015-6940");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pentaho Business Analytics Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pentaho_business_analytics_http_detect.nasl");
  script_mandatory_keys("pentaho/business_analytics/http/detected");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"Pentaho Business Analytics is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to the GetResource servlet, a vestige of the old
  platform UI, allows unauthenticated access to resources in the pentaho-solutions/system folder.
  Specifically vulnerable are properties files that may reveal passwords.");

  script_tag(name:"impact", value:"Successful exploitation will allow unauthenticated access to
  properties files in the system solution which include properties files containing passwords.");

  script_tag(name:"affected", value:"Versions 4.5.x, 4.8.x, 5.0.x, 5.1.x and 5.2.x.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133601");
  script_xref(name:"URL", value:"https://support.pentaho.com/hc/en-us/articles/205782329-Security-Vulnerability-Announcement-Feb-2015");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/GetResource?resource=system/defaultUser.spring.properties";

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern:"defaultAdminUserPassword=", extra_check:"defaultNonAdminUserPassword=")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
