##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_http_srv_cookie_info_disc_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Apache HTTP Server 'httpOnly' Cookie Information Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

CPE = 'cpe:/a:apache:http_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902830");
  script_version("$Revision: 11857 $");
  script_bugtraq_id(51706);
  script_cve_id("CVE-2012-0053");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-26 12:12:12 +0530 (Thu, 26 Apr 2012)");
  script_name("Apache HTTP Server 'httpOnly' Cookie Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web Servers");
  script_require_ports("Services/www", 80);
  script_dependencies("secpod_apache_detect.nasl");
  script_mandatory_keys("apache/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive information
  that may aid in further attacks.");
  script_tag(name:"affected", value:"Apache HTTP Server versions 2.2.0 through 2.2.21");
  script_tag(name:"insight", value:"The flaw is due to an error within the default error response for
  status code 400 when no custom ErrorDocument is configured, which can be
  exploited to expose 'httpOnly' cookies.");
  script_tag(name:"solution", value:"Upgrade to Apache HTTP Server version 2.2.22 or later.");
  script_tag(name:"summary", value:"This host is running Apache HTTP Server and is prone to cookie
  information disclosure vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47779");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18442");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2012-0128.html");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1235454");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2012-02/msg00026.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

exp = crap(820);

for(i=0; i<10; i++) {
  cookie += "c"+ i + "=" + exp + "; path=/; ";
}

host = http_host_name(port:port);

req = string( "GET / HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Cookie: ", cookie, "\r\n\r\n" );

res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if(res && "400 Bad Request" >< res &&
   res =~ "Cookie: c[0-9]=X{820}; path=/;" &&
   "Size of a request header field exceeds server limit" >< res){
  security_message(port:port);
  exit(0);
}

exit(99);