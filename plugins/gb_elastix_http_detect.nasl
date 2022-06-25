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
  script_oid("1.3.6.1.4.1.25623.1.0.117269");
  script_version("2021-03-22T11:05:50+0000");
  script_tag(name:"last_modification", value:"2021-03-22 11:05:50 +0000 (Mon, 22 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-22 09:59:02 +0000 (Mon, 22 Mar 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Elastix Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Elastix.");

  script_xref(name:"URL", value:"http://www.elastix.org/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/elastix", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item: url, port: port );
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
    continue;

  found = 0;

  # <div class="neo-footernote"><a href="http://www.elastix.org" style="text-decoration: none;" target='_blank'>Elastix</a> is licensed under <a href="http://www.opensource.org/licenses/gpl-license.php" style="text-decoration: none;" target='_blank'>GPL</a> by <a href="http://www.palosanto.com" style="text-decoration: none;" target='_blank'>PaloSanto Solutions</a>. 2006 - 2021.</div>
  # <a href="http://www.elastix.com" style="text-decoration: none;" target='_blank'>Elastix</a> is licensed under <a href="http://www.opensource.org/licenses/gpl-license.php" style="text-decoration: none;" target='_blank'>GPL</a> by <a href="http://www.palosanto.com" style="text-decoration: none;" target='_blank'>PaloSanto Solutions</a>. 2006 - 2021.</div>
  #
  # nb: The regex below is using two pattern in one single egrep because the ">Elastix<" is
  # included in the same line as shown above.
  if( concl = egrep( string:buf, pattern:"(>Elastix<|https?://www\.elastix\.(org|com))", icase:FALSE ) ) {
    found++;
    concluded = chomp( concl );
  }

  # <img src="themes/tenant/images/elastix_logo_mini.png" width="200" height="62" alt="elastix logo" />
  if( concl = egrep( string:buf, pattern:"elastix_logo_mini\.png.+elastix logo", icase:FALSE ) ) {
    found++;
    if( concluded )
      concluded += '\n';
    concluded += chomp( concl );
  }

  # <title>Elastix - Login page</title>
  # <title>Elastix - Pagina de Ingreso</title>
  if( concl = egrep( string:buf, pattern:"<title>Elastix", icase:FALSE )  ) {
    found++;
    if( concluded )
      concluded += '\n';
    concluded += chomp( concl );
  }

  if( found > 1 ) {

    set_kb_item( name:"elastix/detected", value:TRUE );
    set_kb_item( name:"elastix/http/detected", value:TRUE );

    concl_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    version = "unknown";

    # nb: Elastix 2.5 was based on CentOS, 5.0 on Debian so we just register Linux here (at least for now).
    register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", desc:"Elastix Detection (HTTP)", runs_key:"unixoide" );

    register_and_report_cpe( app:"Elastix", ver:version, concluded:concluded, base:"cpe:/a:elastix:elastix:",
                             expr:"([0-9.]+)", insloc:install, regPort:port, regService:"www", conclUrl:concl_url );

    exit( 0 );
  }
}

exit( 0 );
