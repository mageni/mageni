###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_coldfusion_detect.nasl 9727 2018-05-04 09:12:47Z cfischer $
#
# ColdFusion Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100773");
  script_version("$Revision: 9727 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-04 11:12:47 +0200 (Fri, 04 May 2018) $");
  script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ColdFusion Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of ColdFusion.

  The script sends a connection request to the server and attempts to
  check the presence of ColdFusion from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

base = '/CFIDE';
file = "/administrator/index.cfm";

url = base + file;

if( http_vuln_check( port:port, url:url, pattern:"<title>ColdFusion Administrator Login</title>", usecache:TRUE ) )
{
  url = base + '/services/pdf.cfc?wsdl';
  req = http_get( item:url, port:port );
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "ColdFusion" >< buf )
  {
    version = eregmatch( pattern:"WSDL created by ColdFusion version ([0-9,]+)-->", string:buf ); # 10.0.10.284825
    if( ! isnull ( version[1] )) cf_version = str_replace( string:version[1], find:",", replace:"." );
  }

  if( ! cf_version )
  {
    url = base + '/adminapi/base.cfc?wsdl';
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "ColdFusion" >< buf )
    {
      version = eregmatch( pattern:"WSDL created by ColdFusion version ([0-9,]+)-->", string:buf ); # (8|9).0.0.251028
      if( ! isnull ( version[1] )) cf_version = str_replace( string:version[1], find:",", replace:"." );
    }

  }

  if( ! cf_version )
  {
    url = base + '/administrator/settings/version.cfm';
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "ColdFusion" >< buf )
    {
      version = eregmatch( pattern:"Version: ([0-9,hf_]+)</strong>", string:buf ); # (6|7).1.0.hf53797_61
      if( ! isnull ( version[1] )) cf_version = str_replace( string:version[1], find:",", replace:"." );
    }
  }

  if( ! cf_version )
  {
    cf_version = 'unknown';
    cpe = 'cpe:/a:adobe:coldfusion';
  }
  else
  {
    cpe = 'cpe:/a:adobe:coldfusion:' + cf_version;
  }

  register_product( cpe:cpe, location:url, port:port );
  set_kb_item(name: string("coldfusion/",port,"/installed"), value: TRUE);
  set_kb_item(name: string("coldfusion/installed"), value: TRUE);

  log_message(data: build_detection_report(app:"Adobe ColdFusion",
                    version: cf_version, install: url, cpe:cpe,
                    concluded: version[0]), port: port);

  exit( 0 );
}

exit( 0 );
