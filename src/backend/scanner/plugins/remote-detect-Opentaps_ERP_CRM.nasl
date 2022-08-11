###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-detect-Opentaps_ERP_CRM.nasl 9944 2018-05-24 09:51:11Z cfischer $
#
# Opentaps ERP + CRM Detection
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101021");
  script_version("$Revision: 9944 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-24 11:51:11 +0200 (Thu, 24 May 2018) $");
  script_tag(name:"creation_date", value:"2009-04-23 00:18:39 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Opentaps ERP + CRM Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host is running Opentaps ERP + CRM.

  Opentaps is a full-featured ERP + CRM suite which incorporates several open source projects, including:

  - Apache Geronimo, Tomcat, and OFBiz for the data model and transaction framework

  - Pentaho and JasperReports for business intelligence

  - Funambol for mobile device and Outlook integration

  - The Opentaps applications which provide user-driven applications for CRM, accounting and finance,
  warehouse and manufacturing, and purchasing and supply chain management.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8080 );

foreach module( make_list( '/activities', '/amazon', '/asterisk', '/catalog', '/crmsfa',
                           '/controllerinjectex', '/dataimport', '/ebay', '/ecommerce', '/financials',
                           '/googlebase', '/opentaps', '/partymgr', '/purchasing', '/search',
                           '/warehouse', '/webstore', '/webtools') ) {

  url = module + "/control/main";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" ) continue;

  # <title> Opentaps Amazon.com Integration Application</title>
  # <title> opentaps DataImport</title>
  # <title>Opentaps Open Source ERP &#43; CRM</title>
  opentapsTitle = eregmatch( pattern:"<title>([a-zA-Z: &#0-9;\.\-]+)</title>", string:res, icase:TRUE );
  if( ( opentapsTitle && 'opentaps' >< tolower( opentapsTitle[1] ) ) || "opentaps_logo.png" >< res ) {

    if( opentapsTitle && 'opentaps' >< tolower( opentapsTitle[1] ) )
      extra_otaps += '\n[' + opentapsTitle[1] + ']:' + report_vuln_url( port:port, url:url, url_only:TRUE );
    else if ( opentapsTitle && 'ofbiz' >< tolower( opentapsTitle[1] ) )
      extra_ofbiz += '\n[' + opentapsTitle[1] + ']:' + report_vuln_url( port:port, url:url, url_only:TRUE );
    else
      extra_otaps += '\n[Unknown module]:' + report_vuln_url( port:port, url:url, url_only:TRUE );

    installed = TRUE;
    set_kb_item( name:"OpentapsERP/" + port + "/modules", value:module );
    if( ! version ) version = "unknown";

    if( version == "unknown" ) {
      # <p><a href="http://www.opentaps.org" class="tabletext">opentaps Open Source ERP + CRM</a> 1.0.0.<br/>
      # <div class="tabletext"><a href="http://www.opentaps.org" class="tabletext">opentaps Open Source ERP + CRM</a> 1.0.0.<br/>
      #         <a href="http://www.opentaps.org">Opentaps Open Source ERP &#43; CRM</a> 1.5.0.<br />
      vers = eregmatch( pattern:'<a href="http://www.opentaps.org"( class="tabletext")?>opentaps[^<]+</a> ([0-9.]+).<br ?/>', string:res, icase:TRUE );
      if( vers[2] ) {
        version = vers[2];
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }
}

if( installed ) {

  set_kb_item( name:"OpentapsERP/installed", value:TRUE );
  set_kb_item( name:"OpentapsERP/" + port + "/version", value:version );
  install = "/";

  if( extra_otaps )
    extra += '\n\nDetected Opentaps Modules:\n' + extra_otaps;

  if( extra_ofbiz )
    extra += '\n\nDetected OFBiz Modules on Opentaps:\n' + extra_ofbiz;

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:opentaps:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:apache:opentaps';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"Opentaps ERP + CRM",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:vers[0] ) + extra, # We don't want to add the "Extra information:" text...
                                            port:port );
}

exit( 0 );
