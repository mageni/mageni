###############################################################################
# OpenVAS Vulnerability Test
# $Id: JBoss_enterprise_aplication_server_detect.nasl 8140 2017-12-15 12:08:32Z cfischer $
#
# JBoss Multiple Products Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100387");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 8140 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 13:08:32 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-12-10 14:34:38 +0100 (Thu, 10 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("JBoss Multiple Products Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "gb_jboss_on_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning", "jboss_on/installed");

  script_xref(name:"URL", value:"https://www.redhat.com/en/technologies/jboss-middleware/application-platform");
  script_xref(name:"URL", value:"http://jbossas.jboss.org/");
  script_xref(name:"URL", value:"http://www.jboss.org/products/eap/overview/");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

if( get_kb_item( "jboss_on/installed" ) ) exit( 0 );

port = get_http_port( default:8080 );

banner = get_http_banner( port:port );
fromErrorBanner = 0;

# "Apache Tomcat/5.5.20", "jboss:4.0.5"
# -> could cause FPs on normal Tomcats
# JBoss AS 5.0.0.GA currently missing
errorStrings = make_array( "JBossWeb/2.0.0.GA", "jboss_application_server:4.2.1", #JBoss AS 4.2.0 and 4.2.1
                           "JBossWeb/2.0.1.GA", "jboss_application_server:4.2.3", #JBoss AS 4.2.2 and 4.2.3
                           "JBoss Web/2.1.2.GA", "jboss_application_server:5.0.1",
                           "JBoss Web/2.1.3.GA", "jboss_application_server:5.1.0",
                           "JBoss Web/3.0.0-CR1", "jboss_application_server:6.0.0",
                           "JBoss Web/3.0.0-CR2", "jboss_application_server:6.1.0",
                           "JBoss Web/7.0.0.CR4", "jboss_application_server:7.0.0",
                           "JBoss Web/7.0.1.Final", "jboss_application_server:7.0.2", #JBoss AS 7.0.1 and 7.0.2
                           "JBoss Web/7.0.10.Final", "jboss_application_server:7.1.0",
                           "JBoss Web/7.0.13.Final", "jboss_application_server:7.1.1",
                           "JBoss Web/7.2.0.Final-redhat-1", "jboss_enterprise_application_platform:6.1",
                           "JBoss Web/7.2.2.Final-redhat-1", "jboss_enterprise_application_platform:6.2",
                           "JBoss Web/7.4.8.Final-redhat-4", "jboss_enterprise_application_platform:6.3",
                           "JBoss Web/7.5.7.Final-redhat-1", "jboss_enterprise_application_platform:6.4" );

# TODO: Also detect from startpage / with if('>JBoss Web Console</' >< res && 'Welcome to JBoss' >< res)

if( egrep( pattern:"X-Powered-By.*JBoss(AS|EAS)?-", string:banner ) ) {

  # TDOD: Currently only major versions (5.0/6) will be detected from banner:
  # JBoss AS 5.0.1.GA, 5.1.0.GA, 6.0.0.Final, 6.1.0.Final
  tmpCpe = "cpe:/a:redhat:jboss_application_server";
  identifier = "jboss_application_server";
  identified = 1;
  appName = "JBoss Application Server";

} else {

  req = http_get( item:"/i_dont_exist", port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  errorBanner = eregmatch( pattern:"(JBoss( )?Web/)[0-9.]+(.|-)(GA|CR[0-9]|Final|Final-redhat-[0-9])", string:res );

  if( errorBanner ) {

    identified = 1;
    fromErrorBanner = 1;
    tmpBanner = errorBanner[0];
    ident = split( errorStrings[tmpBanner], sep:":", keep:FALSE );

    if( ident[0] == "jboss_application_server" ) {
      tmpCpe = "cpe:/a:jboss:jboss_application_server";
      identifier = "jboss_application_server";
      appName = "JBoss Application Server";
      banner = "JBossAS-" + ident[1];
    } else if( ident[0] == "jboss_enterprise_application_platform" ) {
      tmpCpe = "cpe:/a:redhat:jboss_enterprise_application_platform";
      identifier = "jboss_enterprise_application_platform";
      appName = "JBoss Enterprise Application Platform";
      banner = "JBossEAP-" + ident[1];
    } else {
      set_kb_item( name:"jboss/detected", value:TRUE );
      set_kb_item( name:"jboss/port", value:port );
      #No error fingerprint available
      log_message( data:build_detection_report( app:"Unknown JBoss",
                                                version:"unknown",
                                                install:port + '/tcp',
                                                cpe:cpe,
                                                concluded:tmpBanner ),
                                                port:port );
      exit( 0 );
     }
   }
}

if( identified ) {

  vers = 'unknown';
  version = eregmatch( pattern:"JBoss(AS|EAS|EAP)?-([0-9.]+[RC]*[SPGA_CP0-9]*)", string:banner );
  if( ! isnull( version[2] ) ) vers = version[2];

  set_kb_item( name:"www/" + port + "/" + identifier, value:vers );
  set_kb_item( name:identifier + "/installed", value:TRUE );
  set_kb_item( name:"jboss/detected", value:TRUE );
  set_kb_item( name:"jboss/port", value:port );

  cpe = build_cpe( value:vers, exp:"(^[0-9.]+)", base:tmpCpe + ":" );
  if( isnull( cpe ) ) {
    cpe = tmpCpe;
  } else {
    if( vers =~ 'RC[0-9]+|CP[0-9]+|SP[0-9]+|GA+' ) {
      cpe = ereg_replace( pattern:"(\.$)", string:cpe, replace:'' );
      cpeMatch = eregmatch( pattern:"(RC[0-9]+|CP[0-9]+)", string:vers );
      if( ! isnull( cpeMatch[1] ) ) cpe += ':' + tolower( cpeMatch[1] );
    }
  }

  register_product( cpe:cpe, location:port + '/tcp', port:port );

  if( fromErrorBanner ) {
    concl = errorBanner[0];
  } else {
    concl = version[0];
  }

  log_message( data:build_detection_report( app:appName,
                                            version:vers,
                                            install:port + '/tcp',
                                            cpe:cpe,
                                            concluded:concl ),
                                            port:port );
}

exit( 0 );
