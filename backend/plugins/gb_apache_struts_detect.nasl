###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_detect.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# Apache Struts Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800276");
  script_version("$Revision: 10908 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache Struts Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script detects the version of Apache Struts and sets the
  result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

asPort = get_http_port( default:8080 );

foreach dir( make_list_unique("/", "/struts", cgi_dirs( port:asPort ) ) )
{
  install = dir;
  if( dir == "/" ) dir = "";

  ## For some versions path has "/docs/docs/"
  ## While for some versions path has only "/docs"
  foreach url (make_list(dir + "/docs/docs", dir +"/docs"))
  {
    # Main doc page
    ##To confirm application
    rcvRes = http_get_cache( item:url + "/index.html", port:asPort);

    ##Apache Struts2 Version Check from /struts2-core-apidocs/help-doc.html
    sndReq1 = http_get(item:url + "/struts2-core-apidocs/help-doc.html", port:asPort);
    rcvRes1 = http_keepalive_send_recv(port:asPort, data:sndReq1);

    if(rcvRes1 !~ "^HTTP/1\.[01] 200" || "Struts 2 Core" >!< rcvRes1)
    {
      ##Apache Struts2 Version Check from /struts2-core-apidocs/overview-summary.html
      sndReq1 = http_get(item:url + "/struts2-core-apidocs/overview-summary.html", port:asPort);
      rcvRes1 = http_keepalive_send_recv(port:asPort, data:sndReq1);
      if(rcvRes1 !~ "^HTTP/1\.[01] 200" || "Struts 2 Core" >!< rcvRes1)
      {
        ##Apache Struts2 Version Check from /struts2-core-apidocs/index-all.html
        sndReq1 = http_get(item:url + "/struts2-core-apidocs/index-all.html", port:asPort);
        rcvRes1 = http_keepalive_send_recv(port:asPort, data:sndReq1);

        if(rcvRes1 !~ "^HTTP/1\.[01] 200" || "Struts 2 Core" >!< rcvRes1)
        {
          ##src dir
          sndReq2 = http_get(item:dir + "/src/pom.xml", port:asPort);
          rcvRes2 = http_keepalive_send_recv(port:asPort, data:sndReq2);
          if(rcvRes2 !~ "^HTTP/1\.[01] 200" || "Struts 2 Core" >!< rcvRes2)
          {
            sndReq2 = http_get(item:dir + "/src/apps/pom.xml", port:asPort);
            rcvRes2 = http_keepalive_send_recv(port:asPort, data:sndReq2);
          }
        }
      }
    }

    ##Home Doc page
    sndReq3 = http_get(item:url + "/WW/cwiki.apache.org/WW/home.html", port:asPort);
    rcvRes3 = http_keepalive_send_recv(port:asPort, data:sndReq3);

    ##For some versions path is different
    if(rcvRes3 !~ "^HTTP/1\.[01] 200")
    {
      rcvRes3 = http_get_cache( item:url + "/home.html", port:asPort );
    }

    # guides doc page
    sndReq4 = http_get(item:url + "/WW/cwiki.apache.org/WW/guides.html", port:asPort);
    rcvRes4 = http_keepalive_send_recv(port:asPort, data:sndReq4);

    ##For some versions path is different
    if(rcvRes4 !~ "^HTTP/1\.[01] 200")
    {
      sndReq = http_get(item:url + "/guides.html", port:asPort );
      rcvRes4 = http_keepalive_send_recv( port:asPort, data:sndReq );
    }

    ## searching for Struts version in different possible files
    sndReq5 = http_get( item:dir + "/src/src/site/xdoc/index.xml", port:asPort );
    rcvRes5 = http_keepalive_send_recv( port:asPort, data:sndReq5 );

    sndReq6 = http_get( item:dir + "/utils.js", port:asPort );
    rcvRes6 = http_keepalive_send_recv( port:asPort, data:sndReq6 );

    if(("Struts" >< rcvRes && ("Apache" >< rcvRes || "apache" >< rcvRes ) ) ||
        ((("title>API Help" >< rcvRes1) || ('"overviewSummary"' >< rcvRes1) ||
          (rcvRes1 =~ "apache.struts2")) && "Struts 2 Core" >< rcvRes1) ||
        (">Apache Struts 2<" >< rcvRes2 || ">Struts 2 Webapps<" >< rcvRes2) ||
        ( "Getting Started" >< rcvRes3 && "Home" >< rcvRes3 && "Distributions" >< rcvRes3 ) ||
        ( "Migration Guide" >< rcvRes4 && "Core Developers Guide" >< rcvRes4 && "Release Notes" >< rcvRes4 ) ||
          "Apache Struts" >< rcvRes5  || "var StrutsUtils =" >< rcvRes6 )
    {

      strutsVersion = "unknown";

      strutsVer = eregmatch( pattern:"Struts 2 Core ([0-9A-Z.-]+) API", string:rcvRes1);
      if(strutsVer[1]){
        strutsVersion = strutsVer[1];
      } else
      {
        strutsdata = eregmatch( pattern:"<modelVersion(.*)<packaging>", string:rcvRes2);
        strutsVer = eregmatch( pattern:"<version>([0-9A-Z.-]+)</version>", string:strutsdata[1]);
        if(strutsVer[1]){
          strutsVersion = strutsVer[1];
        } else
        {
          strutsVer = eregmatch( pattern:">Version Notes (([0-9]+).([0-9]+).([0-9.]+))", string:rcvRes4);
          ## >Version Notes 2.5.10.1<
          ## guides.html page is not updated after version "2.5.10.1",
          ## So if version is less than 2.5.10.1 , version detection is proper.
          ## Else if version detected is 2.5.10.1, it can be 2.5.10.1 or later.
          if(strutsVer[1] && version_is_less(version: strutsVer[1], test_version: "2.5.10.1")){
            strutsVersion = strutsVer[1];
          } else
          {
            strutsVer = eregmatch( pattern:"Release Notes ([0-9]\.[0-9.]+)", string:rcvRes3);
            if(strutsVer[1]){
              strutsVersion = strutsVer[1];
            } else
            {
              strutsVer = eregmatch( pattern:"Release Notes ([0-9]\.[0-9.]+)", string:rcvRes4 );
              ##>Release Notes 2.0.14<
              ##guides.html page is not updated after version 2.0.14, So if version is less than
              ## 2.0.14, version detection is proper. Else if version detected is 2.0.14,it can be
              ## 2.0.14 or later.
              if(strutsVer[1] && version_is_less(version: strutsVer[1], test_version: "2.0.14")){
                strutsVersion = strutsVer[1];
              } else
              {
                strutsVer = eregmatch( pattern:">version ([0-9.]+)", string:rcvRes5 );
                if(strutsVer[1]){
                  strutsVersion = strutsVer[1];
                }
              }
            }
          }
        }
      }

      tmp_version = strutsVersion + " under " + install;
      set_kb_item( name:"www/" + asPort + "/Apache/Struts", value:tmp_version);
      set_kb_item( name:"ApacheStruts/installed", value:TRUE);

      cpe = build_cpe( value:strutsVersion, exp: "^([0-9A-Z.-]+)", base: "cpe:/a:apache:struts:" );
      if(isnull(cpe))
        cpe = 'cpe:/a:apache:struts';

      register_product(cpe: cpe, location: install, port: asPort);

      log_message( data: build_detection_report( app:"Apache Struts",
                                                 version: strutsVersion,
                                                 install: install,
                                                 cpe: cpe,
                                                 concluded: strutsVer[0]),
                                                 port: asPort);
      exit(0);
    }
  }
}

exit(0);