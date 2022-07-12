##############################################################################
# OpenVAS Vulnerability Test
# $Id: ilohamail_detect.nasl 10802 2018-08-07 08:55:29Z cfischer $
#
# Description: IlohaMail Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004-2005 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14629");
  script_version("$Revision: 10802 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-07 10:55:29 +0200 (Tue, 07 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IlohaMail Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004-2005 George A. Theall");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://ilohamail.org/");

  script_tag(name:"summary", value:"This script detects whether the remote host is running IlohaMail and
  extracts version numbers and locations of any instances found.

  IlohaMail is a webmail application that is based on a stock build of PHP and that does not require either
   a database or a separate IMAP library.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

# NB: Directories beyond cgi_dirs() come from a Google search -
#     'intitle:ilohamail "powered by ilohamail"' - and represent the more
#     popular installation paths currently. Still, cgi_dirs() should
#     catch the directory if its referenced elsewhere on the target.
testdirs = make_list();
foreach dir( make_list( "/webmail", "/ilohamail", "/IlohaMail", "/mail", cgi_dirs( port:port ) ) ) {
  foreach subdir( make_list( "/source", "" ) ) {
    fulldir = str_replace( string: dir + subdir, find:"//", replace:"/" );
    testdirs = make_list( testdirs, fulldir );
  }
}

tesdirs = make_list_unique( testdirs );

foreach dir( testdirs ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( isnull( res ) || res !~ "^HTTP/1\.[01] 200" ) continue;

  if( egrep( string:res, pattern:'>Powered by <a href="http://ilohamail.org">IlohaMail<' ) ||
      egrep( string:res, pattern:"<h2>Welcome to IlohaMail" ) ||
      ( egrep( string:res, pattern:'<input type="hidden" name="logout" value=0>' ) &&
        egrep( string:res, pattern:'<input type="hidden" name="rootdir"' ) &&
        egrep( string:res, pattern:'<input type="password" name="password" value="" size=15' )
      ) ) {

    version = "unknown";
    cpe = "cpe:/a:ilohamail:ilohamail";
    set_kb_item( name:"ilohamail/detected", value:TRUE );

    # nb: Often the version string is embedded in index.php.
    # <br>&nbsp;<h2>Welcome to webmail! </h2>&nbsp;<b> Version 0.8.14-RC2</b><br><br><font color="#FFAAAA"><br>
    # <br>&nbsp;<h2>Welcome to webmail! </h2>&nbsp;<b> Version 0.8.10-Stable</b><br><br>	</td>
    ver = strstr( res, "<b> Version " );
    if( ! isnull( ver ) ) {
      ver = ver - "<b> Version ";
      if( strstr( res, "</b>" ) )
        ver = ver - strstr( ver, "</b>" );
      ver = ereg_replace( string:ver, pattern:"-stable", replace:"", icase:TRUE );
      version = ver;
      if( version =~ "-RC[0-9]+" ) {
        _cpe = ereg_replace( string:version, pattern:"-rc", replace:":rc", icase:TRUE );
        cpe += ":" + _cpe;
      } else {
       cpe += ":" + version;
      }
    }

    register_product( cpe:cpe, location:install, port:port, service:"www" );
    log_message( data:build_detection_report( app:"IlohaMail",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver ),
                                              port:port );
  }
}

exit( 0 );