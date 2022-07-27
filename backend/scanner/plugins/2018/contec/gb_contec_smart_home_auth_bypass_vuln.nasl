##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_contec_smart_home_auth_bypass_vuln.nasl 13515 2019-02-07 07:01:25Z ckuersteiner $
#
# Contec Smart Home Authentication Bypass Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:contec:smart_home";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140937");
  script_version("2019-04-04T07:37:48+0000");
  script_tag(name:"last_modification", value:"2019-04-04 07:37:48 +0000 (Thu, 04 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-04-03 14:47:22 +0700 (Tue, 03 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-9162");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Contec Smart Home Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_contec_smart_home_detect.nasl");
  script_mandatory_keys("contec_smart_home/detected");

  script_tag(name:"summary", value:"Contec Smart Home 4.15 devices do not require authentication for
new_user.php, edit_user.php, delete_user.php, and user.php, as demonstrated by changing the admin password and
then obtaining control over doors.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44295/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/content/user.php";

if (http_vuln_check(port: port, url: url, pattern: 'class="list home"', check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
