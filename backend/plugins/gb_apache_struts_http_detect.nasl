# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800276");
  script_version("2021-04-01T05:54:23+0000");
  script_tag(name:"last_modification", value:"2021-04-01 10:13:05 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache Struts Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Struts.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/", "/struts", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  # nb: For some versions path has "/docs/docs/" while for some versions path has only "/docs"
  foreach subdir( make_list( dir, dir + "/docs/docs", dir + "/docs" ) ) {

    # nb: Main doc page to confirm the application
    res = http_get_cache( item:subdir + "/index.html", port:port );

    foreach file( make_list( subdir + "/struts2-core-apidocs/help-doc.html",
                             subdir + "/struts2-core-apidocs/overview-summary.html", 
                             subdir + "/struts2-core-apidocs/index-all.html" ) ) {

      res1 = http_get_cache( item:file, port:port );
      if( ! res1 || res1 !~ "^HTTP/1\.[01] 200" || "Struts 2 Core" >!< res1 ) {
        continue;
      } else {
        concl_url1 = http_report_vuln_url( port:port, url:file, url_only:TRUE );
        break;
      }
    }

    foreach url2( make_list( dir + "/src/pom.xml", dir + "/src/apps/pom.xml" ) ) {
      res2 = http_get_cache( item:url2, port:port );
      if( ! res2 || res2 !~ "^HTTP/1\.[01] 200" || "<name>Struts 2" >!< res2 ) {
        continue;
      } else {
        concl_url2 = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
        break;
      }
    }

    foreach url3( make_list( subdir + "/WW/cwiki.apache.org/WW/home.html", subdir + "/home.html" ) ) {
      res3 = http_get_cache( item:url3, port:port );
      if( ! res3 || res3 !~ "^HTTP/1\.[01] 200" ) {
        continue;
      } else {
        concl_url3 = http_report_vuln_url( port:port, url:url3, url_only:TRUE );
        break;
      }
    }

    foreach url4( make_list( subdir + "/WW/cwiki.apache.org/WW/guides.html", subdir + "/guides.html" ) ) {
      res4 = http_get_cache( item:url4, port:port );
      if( ! res4 || res4 !~ "^HTTP/1\.[01] 200" ) {
        continue;
      } else {
        concl_url4 = http_report_vuln_url( port:port, url:url4, url_only:TRUE );
        break;
      }
    }

    concl_url5 = dir + "/src/src/site/xdoc/index.xml";
    res5 = http_get_cache( item:concl_url5, port:port );

    concl_url6 = dir + "/utils.js";
    res6 = http_get_cache( item:concl_url6, port:port );

    if( ( "Struts" >< res && ( "Apache" >< res || "apache" >< res ) ) ||
        ( ( "title>API Help" >< res1 || '"overviewSummary"' >< res1 || res1 =~ "apache.struts2" ) &&
            "Struts 2 Core" >< res1 ) ||
        ( ">Apache Struts 2<" >< res2 || ">Struts 2 Webapps<" >< res2 ) ||
        ( "Getting Started" >< res3 && "Home" >< res3 && "Distributions" >< res3 ) ||
        ( "Migration Guide" >< res4 && "Core Developers Guide" >< res4 && "Release Notes" >< res4 ) ||
        "Apache Struts" >< res5 || "var StrutsUtils =" >< res6 ) {

      strutsVersion = "unknown";

      strutsVer = eregmatch( pattern:"Struts 2 Core ([0-9A-Z.-]+) API", string:res1 );
      if( strutsVer[1] ) {
        strutsVersion = strutsVer[1];
        concl_url = concl_url1;
      } 

      if( strutsVersion == "unknown" ) {
        strutsdata = eregmatch( pattern:"<modelVersion(.*)<packaging>", string:res2 );
        strutsVer = eregmatch( pattern:"<version>([0-9A-Z.-]+)</version>", string:strutsdata[1] );
        if( strutsVer[1] ) {
          strutsVersion = strutsVer[1];
          concl_url = concl_url2;
        }
      }

      if( strutsVersion == "unknown" ) {
        # >Version Notes 2.5.10.1<
        strutsVer = eregmatch( pattern:">Version Notes (([0-9]+).([0-9]+).([0-9.]+))", string:res4 );
        # nb: guides.html page is not updated after version "2.5.10.1".
        # So if version is less than 2.5.10.1, version detection is proper.
        # Else if version detected is 2.5.10.1, it can be 2.5.10.1 or later.
        if( strutsVer[1] && version_is_less( version:strutsVer[1], test_version:"2.5.10.1" ) ) {
          strutsVersion = strutsVer[1];
          concl_url = concl_url4;
        }
      }

      if( strutsVersion == "unknown" ) {
        strutsVer = eregmatch( pattern:"Release Notes ([0-9]\.[0-9.]+)", string:res3 );
        if( strutsVer[1] ) {
          strutsVersion = strutsVer[1];
          concl_url = concl_url3;
        }
      }

      if( strutsVersion == "unknown" ) {
        # >Release Notes 2.0.14<
        strutsVer = eregmatch( pattern:"Release Notes ([0-9]\.[0-9.]+)", string:res4 );
        # nb: guides.html page is not updated after version 2.0.14, So if version is less than
        # 2.0.14, version detection is proper. Else if version detected is 2.0.14, it can be 2.0.14 or later.
        if( strutsVer[1] && version_is_less( version:strutsVer[1], test_version:"2.0.14" ) ) {
          strutsVersion = strutsVer[1];
          concl_url = concl_url4;
        }
      }

      if( strutsVersion == "unknown" ) {
        strutsVer = eregmatch( pattern:">version ([0-9.]+)", string:res5 );
        if( strutsVer[1] ) {
          strutsVersion = strutsVer[1];
          concl_url = concl_url5;
        }
      }

      set_kb_item( name:"apache/struts/detected", value:TRUE );
      set_kb_item( name:"apache/struts/http/detected", value:TRUE );
      set_kb_item( name:"apache/struts/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + strutsVersion + "#---#" + strutsVer[0] + "#---##---#" + concl_url );

      exit( 0 );
    }
  }
}

exit( 0 );