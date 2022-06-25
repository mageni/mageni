# Copyright (C) 2002 Matt Moore
# New NASL code Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.11037");
  script_version("2021-02-11T12:27:12+0000");
  script_tag(name:"last_modification", value:"2021-02-12 11:04:26 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1855", "CVE-2002-1856", "CVE-2002-1857", "CVE-2002-1858",
                "CVE-2002-1859", "CVE-2002-1860", "CVE-2002-1861", "CVE-2016-0793");
  script_bugtraq_id(5119);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("'/WEB-INF./' Information Disclosure Vulnerability (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.westpoint.ltd.uk/advisories/wp-02-0002.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/136323/Wildfly-Filter-Restriction-Bypass-Information-Disclosure.html");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39573");
  script_xref(name:"URL", value:"https://security.netapp.com/advisory/ntap-20180215-0001/");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-hpesbhf03784en_us");

  script_tag(name:"summary", value:"Various application or web servers / products are prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"The following products are known to be affected:

  - Sybase EA Server 4.0

  - OC4J - Oracle Containers for J2EE

  - Orion 1.5.3

  - JRun 3.0, 3.1 and JRun 4 - Macromedia / Allaire JRun

  - HPAS 8.0 - Hewlett Packard App Server

  - Pramati 3.0 - Pramati App Server

  - WildFly (formerly JBoss Application Server) before 10.0.0.Final

  - HPE B-Series SAN Network Advisor Software Running WildFly (formerly JBoss Application Server)

  Other products might be affected as well.");

  script_tag(name:"insight", value:"The servlet specification prohibits servlet containers from serving resources
  in the '/WEB-INF' and '/META-INF' directories of a web application archive directly to clients.

  This means that URLs like:

  http://example.com/WEB-INF/web.xml

  will return an error message, rather than the contents of the deployment descriptor.

  However, some application or web servers / products are prone to a vulnerability that exposes this information if
  the client requests a URL like this instead:

  http://example.com/WEB-INF./web.xml

  http://example.com/web-inf./web.xml

  (note the trailing dot ('.') after 'WEB-INF').");

  script_tag(name:"impact", value:"Based on the information provided in this file an attacker might be able to gather
  additional info and/or sensitive data about the application / the application / web server.");

  script_tag(name:"solution", value:"The following vendor fixes are known:

  - Update WildFly to version 10.0.0.Final or later.

  For other products please contact the vendor for more information on possible fixes.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

base_pattern  = "^\s*<(web-app( .+|>$)|servlet>$)";
extra_pattern = "^\s*</(web-app|servlet)>$";

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/", "/h2console", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/WEB-INF./web.xml";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( res && egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) ) {
    report  = http_report_vuln_url( port:port, url:url );
    report += '\nResponse (truncated):\n\n' + substr( res, 0, 1500 );
    security_message( port:port, data:report );
    exit( 0 );
  }

  # We want to check the lowercase variant as well (from CVE-2016-0793).
  url = str_replace( string:url, find:"/WEB-INF./web.xml", replace:"/web-inf./web.xml" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( ! res )
    continue;

  if( egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) ) {
    report  = http_report_vuln_url( port:port, url:url );
    report += '\nResponse (truncated):\n\n' + substr( res, 0, 1500 );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );