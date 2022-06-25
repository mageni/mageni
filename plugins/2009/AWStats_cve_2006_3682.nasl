###############################################################################
# OpenVAS Vulnerability Test
# $Id: AWStats_cve_2006_3682.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# AWStats 'awstats.pl' Multiple Path Disclosure Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:awstats:awstats";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100070");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-22 17:08:49 +0100 (Sun, 22 Mar 2009)");
  script_bugtraq_id(34159);
  script_cve_id("CVE-2006-3682");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("AWStats 'awstats.pl' Multiple Path Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("awstats_detect.nasl");
  script_mandatory_keys("awstats/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34159");

  script_tag(name:"summary", value:"AWStats is prone to a path-disclosure vulnerability.");

  script_tag(name:"affected", value:"AWStats 6.5 (build 1.857) and prior WebGUI Runtime Environment 0.8.x and
  prior");

  script_tag(name:"impact", value:"Exploiting this issue can allow an attacker to access sensitive data that may
  be used to launch further attacks against a vulnerable computer.");

  script_tag(name:"solution", value:"Please update to AWStats 6.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

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

url = dir + "/awstats.pl?config=VT-Test";

if (http_vuln_check(port: port, url: url,
                    pattern: 'Error:.*config file "awstats.VT-Test.conf".*after searching in path.*')) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);