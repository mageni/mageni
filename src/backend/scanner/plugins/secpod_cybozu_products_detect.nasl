###############################################################################
# OpenVAS Vulnerability Test
#
# Cybozu Products Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902533");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Cybozu Products Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the running Cybozu Products version and
  saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

# TBD: The products seems to be running on Unixoide OS as well. Are the files
# for an installation on such an OS are really ending with .exe?

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/scripts", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  ## Cybozu Garoon
  foreach path( make_list( "", "/cbgrn", "/garoon", "/grn" ) ) {

    install = dir + path;

    req = http_get( item: install + "/grn.exe", port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 200" && "Cybozu" >< res && "Garoon" >< res ) {

      version = "unknown";

      ver = eregmatch( pattern:"Version ([0-9.]+)", string:res );
      if( ver[1] ) version = ver[1];

      tmp_version = version + " under " + install;
      set_kb_item( name:"www/" + port + "/CybozuGaroon", value:tmp_version );
      set_kb_item( name:"CybozuGaroon/Installed", value:TRUE );
      set_kb_item( name:"cybozu_products/detected", value:TRUE );

      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cybozu:garoon:" );
      if( isnull( cpe ) )
        cpe = 'cpe:/a:cybozu:garoon';

      register_product( cpe:cpe, location:install, port:port );

      log_message( data:build_detection_report( app:"Cybozu Garoon",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:ver[0] ),
                                                port:port );
    }
  }

  ## Cybozu Office
  foreach path( make_list( "", "/cbag", "/office", "/cgi-bin/cbag" ) ) {

    foreach file( make_list("/ag.exe", "/ag.cgi" ) ) {

      install = dir + path;

      req = http_get( item:install + file, port:port );
      res = http_keepalive_send_recv( port:port, data:req );

      if( res =~ "^HTTP/1\.[01] 200" && "Cybozu" >< res && "Office" >< res ) {

        version = "unknown";

        ver = eregmatch( pattern:"Office Version ([0-9.]+)", string:res );
        if( ver[1] ) version = ver[1];

        tmp_version = version + " under " + install;
        set_kb_item( name:"CybozuOffice/Installed", value:TRUE );
        set_kb_item( name:"www/" + port + "/CybozuOffice", value:tmp_version );
        set_kb_item( name:"cybozu_products/detected", value:TRUE );

        cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cybozu:office:" );
        if( isnull( cpe ) )
          cpe = 'cpe:/a:cybozu:office';

        register_product( cpe:cpe, location:install, port:port );

        log_message( data:build_detection_report( app:"Cybozu Office",
                                                  version:version,
                                                  install:install,
                                                  cpe:cpe,
                                                  concluded:ver[0] ),
                                                  port:port );
      }
    }
  }

  ## Cybozu Dezie
  foreach path( make_list( "", "/cbdb", "/dezie" ) ) {

    install = dir + path;

    req = http_get( item:install + "/db.exe", port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 200" && "Cybozu" >< res && "Dezie" >< res ) {

      version = "unknown";

      ver = eregmatch( pattern:"Version ([0-9.]+)", string:res );
      if( ver[1] ) version = ver[1];

      tmp_version = version + " under " + install;
      set_kb_item( name:"CybozuDezie/Installed", value:TRUE );
      set_kb_item( name:"www/" + port + "/CybozuDezie", value:tmp_version );
      set_kb_item( name:"cybozu_products/detected", value:TRUE );

      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cybozu:dezie:" );
      if( isnull( cpe ) )
        cpe = 'cpe:/a:cybozu:dezie';

      register_product( cpe:cpe, location:install, port:port );

      log_message( data:build_detection_report( app:"Cybozu Dezie",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:ver[0] ),
                                                port:port );
    }
  }

  ## Cybozu MailWise
  foreach path( make_list( "", "/cbmw", "/mailwise" ) ) {

    install = dir + path;

    req = http_get( item:install + "/mw.exe", port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 200" && "Cybozu" >< res && "mailwise" >< res ) {

      version = "unknown";

      ver = eregmatch( pattern:"Version ([0-9.]+)", string:res );
      if( ver[1] ) version = ver[1];

      tmp_version = version + " under " + install;
      set_kb_item( name:"CybozuMailWise/Installed", value:TRUE );
      set_kb_item( name:"www/" + port + "/CybozuMailWise", value:tmp_version );
      set_kb_item( name:"cybozu_products/detected", value:TRUE );

      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cybozu:mailwise:" );
      if( isnull( cpe ) )
        cpe = 'cpe:/a:cybozu:mailwise';

      register_product( cpe:cpe, location:install, port:port );

      log_message( data:build_detection_report( app:"Cybozu MailWise",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:ver[0] ),
                                                port:port );
    }
  }
}

exit( 0 );
