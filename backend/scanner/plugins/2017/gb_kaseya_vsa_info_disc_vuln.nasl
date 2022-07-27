###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaseya_vsa_info_disc_vuln.nasl 13512 2019-02-07 02:04:24Z ckuersteiner $
#
# Kaseya VSA Information Disclosure Vulnerability
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

CPE = 'cpe:/a:kaseya:virtual_system_administrator';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106739");
  script_version("$Revision: 13512 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-07 03:04:24 +0100 (Thu, 07 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-04-10 14:46:29 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Kaseya VSA Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kaseya_vsa_detect.nasl");
  script_mandatory_keys("kaseya_vsa/installed");

  script_tag(name:"summary", value:"Kaseya VSA is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a HTTP request and checks the response.");

  script_tag(name:"insight", value:"Requests to /install/kaseya.html reveals sensitive information about the
application and its underlying system.");

  script_tag(name:"impact", value:"An unauthenticated attacker may obtain sensitive information about the
application and its underlying system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.osisecurity.com.au/kaseya-information-disclosure-vulnerability.html");

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

url = dir + "/install/kaseya.html";
if (http_vuln_check(port: port, url: url, pattern: "IFX_INSTALLED_VERSION",
                    check_header: TRUE, extra_check: "SUPPORTDIR")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
