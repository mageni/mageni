# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103786");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-11-02T10:36:36+0000");
  script_tag(name:"last_modification", value:"2022-11-02 10:36:36 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"creation_date", value:"2013-09-12 10:58:59 +0200 (Thu, 12 Sep 2013)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology DiskStation Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Synology NAS devices, DiskStation Manager
  (DSM) OS and application.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("http_keepalive.inc");

# @brief Takes the build number argument and returns a full version based on the release notes from
#        https://www.synology.com/en-us/releaseNote/DSM

# @param buildNumber the build number of the release
#
# @return A string containing the full version
#
# @note This mapping is based on intervals of builds numbers. Rather than using the greatest build number for a certain version,
#       it is using the smallest build number of the next version, as exclusive upper limit.
#       The decision to do it this way came from the fact that, 4.3-3827 Update 8 is the last release for 4.3 in the Release Notes,
#       but actually there were targets with 4.3-4244
function mapBuildToVersion( buildNumber ) {

  local_var buildNumber, int_ver;

  # nb: No "!buildNumber" because there might be also a build number of "0" (if that can ever happen)
  if( isnull( buildNumber ) )
    return NULL;

  int_ver = int( buildNumber );
  if( int_ver < 318 )
    return "1.0-" + buildNumber;
  if( int_ver < 832 )
    return "2.0-" + buildNumber;
  if( int_ver < 942 )
    return "2.1-" + buildNumber;
  if( int_ver < 1139 )
    return "2.2-" + buildNumber;
  if( int_ver < 1334 )
    return "2.3-" + buildNumber;
  if( int_ver < 1594 )
    return "3.0-" + buildNumber;
  if( int_ver < 1922 )
    return "3.1-" + buildNumber;
  if( int_ver < 2197 )
    return "3.2-" + buildNumber;
  if( int_ver < 2636 )
    return "4.0-" + buildNumber;
  if( int_ver < 3202 )
    return "4.1-" + buildNumber;
  if( int_ver < 3776 )
    return "4.2-" + buildNumber;
  if( int_ver < 4458 )
    return "4.3-" + buildNumber;
  # nb: For higher versions, the number extracted from the "v" URL parameter is no longer the build number.
  # Therefore, it makes no sense to continue this mapping, as it will never be used above the 4.3 version.
  return NULL;
}

port = http_get_port( default:5000 );

install = "/";

foreach url( make_list( "/webman/index.cgi", "/index.cgi" ) ) {
  buf = http_get_cache( item:url, port:port );
  # nb: old detection rules do not work anymore for newer versions
  if( ( ( buf =~ "Synology(&nbsp;| )DiskStation") || ( buf =~ "synology\.com" && ( 'content="DiskStation' >< buf  || "synoSDSjslib/sds.js" >< buf ) ) ) &&
    ( buf =~ "SYNO\.(SDS.Session|Core.Desktop)" || buf =~ '<meta name="description" content="(VirtualDSM|Synology NAS|DiskStation) provides a full-featured' ) )
  {
    concl = "";
    version = "unknown";
    concUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"synology/dsm/detected",value:TRUE );
    set_kb_item( name:"synology/dsm/http/detected", value:TRUE );
    set_kb_item( name:"synology/dsm/http/port", value:port );

    # nb: this only works for newer versions, from 6.x onward
    url1 = "/synohdpack/synohdpack.version";
    #majorversion="7"
    #minorversion="1"
    #major="7"
    #minor="1"
    #micro="1"
    #productversion="7.1.1"
    #buildphase="GM"
    #buildnumber="42962"
    #smallfixnumber="0"
    #nano="0"
    #base="42962"
    res = http_get_cache( item:url1, port:port );
    if( ! isnull( res ) && res =~ "^HTTP/(1\.[01]|2) 200" ) {

      ver = eregmatch( pattern:'productversion="([0-9.]+)"', string:res );
      if( ! isnull( ver[1] ) ) {
        version = ver[1];
        concUrl += '\n  ' + http_report_vuln_url( port:port, url:url1, url_only:TRUE );
        concl += '\n  ' + ver[0];
      } else {
        # nb: Version 5.0 has this file, but there is no "productversion" entry, so we use the majorversion.minorversion
        # since on those versions there were no micro versions used, as far as Release Notes can tell, it should be ok
        ver = eregmatch( pattern:'majorversion="([0-9]+)"', string:res );
        if( ! isnull( ver[1] ) ) {
          version = ver[1];
          concUrl += '\n  ' + http_report_vuln_url( port:port, url:url1, url_only:TRUE );
          concl += '\n  ' + ver[0];

          ver1 = eregmatch( pattern:'minorversion="([0-9]+)"', string:res );
          if( ! isnull( ver1[1] ) ) {
            version += "." + ver1[1];
            concl += '\n  ' + ver1[0];
          }
        }
      }
      # nb: we can add now build number and small fix number
      if( "unknown" >!< version ) {
        ver1 = eregmatch( pattern:'buildnumber="([0-9]+)"', string:res );
        if( ! isnull( ver1[1] ) ) {
          version += "-" + ver1[1];
          concl += '\n  ' + ver1[0];
        }

        ver2 = eregmatch( pattern:'smallfixnumber="([0-9]+)"', string:res );
        if( ! isnull( ver2[1] ) && int( ver2[1] ) > 0 ) {
          version += "-" + ver2[1];
          concl += '\n  ' + ver2[0];
        }
      }
    } else {
      # nb: For older versions ( < 4.3 ) the above solution does not work, but we can extract buildNumber
      # and based on the release history, we can reconstruct full version
      # see https://www.synology.com/en-us/releaseNote/DSM

      # nb: Starting with 4.3 versions, the syndefs.cgi method is no longer reliable, as the number after is no longer the build number
      # Instead, a "fullversion" entry got added in the SYNO.SDS.Session JSON, containing the build number.
      # eg. "fullversion" : "3810-s0"
      ver = eregmatch( pattern:'"fullversion"\\s*:\\s*"([0-9]+)([0-9a-z-]+)?"', string:buf );

      if( ! isnull( ver[1] ) ) {
        ver_str = mapBuildToVersion( buildNumber:ver[1] );
        if( ! isnull( ver_str ) ) {
          version = ver_str;
          concl += '\n  ' + ver[0];
        }
      } else {
        # nb: Versions 4.2 and lower contain the build number in the syndefs.cgi?v=<nr>. They also might contain a "version" entry in the
        # SYNO.SDS.Session JSON, but that did not happen for version 3.0 - 3.2. Could not find targets 2.x and below.
        ver = eregmatch( pattern:'<script type="text/javascript" src="synodefs\\.cgi\\?v=([0-9]+)', string:buf );

        if( ! isnull( ver[1] ) ) {
          ver_str = mapBuildToVersion( buildNumber:ver[1] );
          if( ! isnull( ver_str ) )
            version = ver_str;
            concl += '\n  ' + ver[0];
        }
      }
    }
    # nb: Try to extract model from here. Works only for versions < 6.0
    url = "/webman/synodefs.cgi";
    res = http_get_cache( item:url, port:port );
    if( res && res =~ "^HTTP/(1\.[01]|2) 200" ) {

      # eg: "upnpmodelname":"DS3615xs"
      mod = eregmatch( pattern:'"upnpmodelname":"([a-zA-Z0-9+]+)"', string:res );
      if( ! isnull( mod[1] ) ) {
        set_kb_item( name:"synology/dsm/http/" + port + "/model", value:mod[1] );
        concl += '\n  ' +mod[0];
        concUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    set_kb_item( name:"synology/dsm/http/" + port + "/version", value:version );

    if( concl )
      set_kb_item( name:"synology/dsm/http/" + port + "/concluded", value:chomp( concl ) );

    if( concUrl )
      set_kb_item( name:"synology/dsm/http/" + port + "/concludedUrl", value:concUrl );

    exit( 0 );
  }
}
exit( 0 );
