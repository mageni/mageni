# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117224");
  script_version("2021-02-12T08:16:09+0000");
  script_cve_id("CVE-2004-2734", "CVE-2014-0053", "CVE-2014-2857", "CVE-2014-2858");
  script_bugtraq_id(65678);
  script_tag(name:"last_modification", value:"2021-02-12 11:04:26 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-11 15:27:45 +0000 (Thu, 11 Feb 2021)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"cvss_base", value:"10.0");
  script_name("'/WEB-INF/' Information Disclosure Vulnerability (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://tanzu.vmware.com/security/cve-2014-0053");
  script_xref(name:"URL", value:"https://support.microfocus.com/kb/doc.php?id=10094233");

  script_tag(name:"summary", value:"Various application or web servers / products are prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"The following products are known to be affected:

  - Grails Resources plugin 1.0.0 to 1.2.5 as used in Grails 2.0.0 to 2.3.6.

  - Novell Web Manager on Novell NetWare 6.5.

  Other products might be affected as well.");

  script_tag(name:"insight", value:"The servlet specification prohibits servlet containers from serving resources
  in the '/WEB-INF' and '/META-INF' directories of a web application archive directly to clients.

  This means that URLs like:

  http://example.com/WEB-INF/web.xml

  will return an error message, rather than the contents of the deployment descriptor.

  However, some application or web servers / products are prone to a vulnerability that still exposes this information
  if the client requests the URL directly.");

  script_tag(name:"impact", value:"Based on the information provided in this file an attacker might be able to gather
  additional info and/or sensitive data about the application / the application / web server.");

  script_tag(name:"solution", value:"The following vendor fixes are known:

  - Update the Grails Resources plug-in to 1.2.6 or later.

  - Update Novell Web Manager to Support Pack 2 (NW6.5 SP2) or later.

  For other products please contact the vendor for more information on possible fixes.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

base_pattern  = "^\s*<(web-app( .+|>$)|servlet>$)";
extra_pattern = "^\s*</(web-app|servlet)>$";

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/", "/WebAdmin", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/WEB-INF/web.xml";

  res = http_get_cache( item:url, port:port );
  if( ! res )
    continue;

  res = http_extract_body_from_response( data:res );

  if( res && egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) ) {
    report  = http_report_vuln_url( port:port, url:url );
    report += '\nResponse (truncated):\n\n' + substr( res, 0, 1500 );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );