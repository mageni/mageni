###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opennms_mult_vuln.nasl 14121 2019-03-13 06:21:23Z ckuersteiner $
#
# OpenNMS Default Credentials and XXE Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:opennms:opennms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806531");
  script_version("$Revision: 14121 $");
  script_cve_id("CVE-2015-7856", "CVE-2015-0975");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 07:21:23 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-11-04 13:01:47 +0530 (Wed, 04 Nov 2015)");

  script_name("OpenNMS Default Credentials and XXE Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("opennms_detect.nasl");
  script_mandatory_keys("OpenNms/Installed");
  script_require_ports("Services/www", 8980);

  script_xref(name:"URL", value:"http://www.opennms.org/wiki/CVE-2015-0975");
  script_xref(name:"URL", value:"http://kvspmufc.appspot.com/www.scip.ch/?vuldb.78543");
  script_xref(name:"URL", value:"http://www.rapid7.com/db/modules/auxiliary/gather/opennms_xxe");

  script_tag(name:"summary", value:"This host is running OpenNMS and is prone to
  default credentials and XXE vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST and
  check whether it is able to bypass authentication or not.");

  script_tag(name:"insight", value:"Multiple flaws exists as,

  - It is possible to login with default credentials: rtc/rtc.

  - The OpenNMS is vulnerable to XML External Entity Injection in the Real-Time
    Console interface.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to obtain access by leveraging knowledge of the credentials and
  launch further attacks including XML External Entity Injection.");

  script_tag(name:"affected", value:"OpenNMS versions prior to 14.0.3");

  script_tag(name:"solution", value:"Upgrade to OpenNMS version 14.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

host = http_host_name( port:port );

url = dir + "/login.jsp";

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req );

if( "OpenNMS Group, Inc." >< buf ) {

  cookie = eregmatch( pattern:"JSESSIONID=([0-9a-zA-Z]+);", string:buf );
  if( ! cookie[1] ) exit( 0 );

  post_data = "j_username=rtc&j_password=rtc&Login=&j_usergroups=";
  len = strlen( post_data );

  req = 'POST ' + dir + '/j_spring_security_check HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Cookie: JSESSIONID=' + cookie[1] + '; ' + 'JSESSIONID=' + cookie[1] + '\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        post_data;
  buf = http_keepalive_send_recv( port:port, data:req );

  if( "HTTP/1.1 302 Found" >< buf  && "?login_error=1" >!<  buf &&
      buf =~ "Location:.*/index.jsp" ) {

    req = 'GET ' + dir + '/frontPage.htm HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'Cookie: JSESSIONID=' + cookie[1] + '; ' + 'JSESSIONID=' + cookie[1] + '\r\n' + '\r\n';
    buf = http_keepalive_send_recv( port:port, data:req );

    if( ">Statistics<" >< buf && ">Dashboard<" >< buf &&
        ">Change Password<" >< buf && ">Log Out<"  >< buf &&
        ">The OpenNMS Group, Inc." >< buf ) {
      report = 'It was possible to login with default credentials rtc/rtc at:\n' +
               report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
