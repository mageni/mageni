###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zoneminder_info_disc_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# ZoneMinder Information Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:zoneminder:zoneminder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106521");
  script_version("$Revision: 11982 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-17 13:28:38 +0700 (Tue, 17 Jan 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-10140");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("ZoneMinder Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_detect.nasl");
  script_mandatory_keys("zoneminder/installed");

  script_tag(name:"summary", value:"ZoneMinder is prone to an information disclosure and authentication
bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to get a directory listing on the /events/ folder.");

  script_tag(name:"insight", value:"Information disclosure and authentication bypass vulnerability exists in
the Apache HTTP Server configuration bundled with ZoneMinder, which allows a remote unauthenticated attacker to
browse all directories in the web root, e.g., a remote unauthenticated attacker can view all CCTV images on the
server.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may browse all directories in the web
root.");

  script_tag(name:"solution", value:"Disable directory listings in the apache configuration.");

  script_xref(name:"URL", value:"https://github.com/ZoneMinder/ZoneMinder/pull/1697");

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

if (http_vuln_check(port: port, url: dir + "/events/", pattern: "<title>Index of.*/events</title>",
                    check_header: TRUE)) {
  report = report_vuln_url(port: port, url: dir + "/events/");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
