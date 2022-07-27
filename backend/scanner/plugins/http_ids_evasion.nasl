###############################################################################
# OpenVAS Vulnerability Test
# $Id: http_ids_evasion.nasl 13870 2019-02-26 09:30:12Z cfischer $
#
# HTTP NIDS evasion
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi / Renaud Deraison
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
###############################################################################

# The HTTP IDS evasion mode comes from Whisker, by RFP.
# Read http://www.wiretrip.net/rfp/pages/whitepapers/whiskerids.html

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80010");
  script_version("$Revision: 13870 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 10:30:12 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 19:16:58 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HTTP NIDS evasion");
  script_category(ACT_SETTINGS);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi / Renaud Deraison");
  script_family("Settings");

  script_xref(name:"URL", value:"http://www.wiretrip.net/rfp/pages/whitepapers/whiskerids.html");

  script_add_preference(name:"Enable HTTP evasion techniques", type:"checkbox", value:"no");

  script_add_preference(name:"Use HTTP HEAD instead of GET", type:"checkbox", value:"no");
  script_add_preference(name:"URL encoding", type:"radio", value:"none;Hex;UTF-16 (double byte); UTF-16 (MS %u);Incorrect UTF-8");
  # Pavel kankovsky's suggestion
  script_add_preference(name:"Absolute URI type", type:"radio", value:"none;file;gopher;http");
  script_add_preference(name:"Absolute URI host", type:"radio", value:"none;host name;host IP;random name;random IP");

  script_add_preference(name:"Double slashes", type:"checkbox", value:"no");
  script_add_preference(name:"Reverse traversal", type:"radio", value:"none;Basic;Long URL");

  script_add_preference(name:"Self-reference directories", type:"checkbox", value:"no");
  script_add_preference(name:"Premature request ending", type:"checkbox", value:"no");
  # CGI.pm "anti NIDS" discovered by Securiteam
  script_add_preference(name:"CGI.pm semicolon separator", type:"checkbox", value:"no");
  script_add_preference(name:"Parameter hiding", type:"checkbox", value:"no");
  script_add_preference(name:"Dos/Windows syntax", type:"checkbox", value:"no");
  script_add_preference(name:"Null method", type:"checkbox", value:"no");
  script_add_preference(name:"TAB separator", type:"checkbox", value:"no");
  script_add_preference(name:"HTTP/0.9 requests", type:"checkbox", value:"no");

  script_add_preference(name:"Force protocol string : ", type:"entry", value:"");
  script_add_preference(name:"Random case sensitivity (Nikto only)", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This plugin configures Scanner for NIDS evasion (see the 'Prefs' panel).
  NIDS evasion options are useful if you want to determine the quality of the expensive NIDS you just bought.

  HTTP evasion techniques :

  - Use HTTP HEAD instead of GET

  - URL encoding:

  - - Hex: change characters to %XX

  - - UTF-16 (double byte): change characters to %00%XX. This should *not* work!

  - - UTF-16 (MS %u): change characters to %uXXXX. This works only with IIS.

  - - Incorrect UTF-8: change characters to invalid multibyte UTF8 sequences.

  - Absolute URI: insert scheme://host/ in front of the relative URI.

  - Double slashes: change every / to //

  - Reverse traversal: change / into /dirname/../

  - - 'Basic' inserts 8 characters random directory names

  - - 'Long' means 1000 character directory name.

  - Self-reference directories: changes every / to /./

  - Premature request ending: just like 'reverse traversal', but the directory
  name contains %0d%0a (could be translated to CR LF)

  - CGI.pm semicolon separator: uses a semicolon instead of '&' in the query string.

  - Parameter hiding: another form of reverse traversal. The directory contains
  %3F (could be translated to ?)

  - Dos/Windows syntax: uses \ instead of /

  - Null method: insert %00 between the method and the URI

  - TAB separator: uses TAB instead of SPACE between the method, the URL and the HTTP
  version

  - HTTP/0.9 requests: uses HTTP/0.9 requests (method & URI only, no HTTP version field)

  'Premature request ending' and 'Parameter hiding' target 'smart' IDS.

  See the references for more information.

  Warning: those features are experimental and some options may result in false negatives!

  This plugin does not do any security check.");

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

# TBD: Implement "Random case sensitivity" from Nikto

whisker_nids = 'X';
warn = FALSE;

opt = script_get_preference( "Enable HTTP evasion techniques" );
if( opt != "yes" ) exit( 0 );

opt = script_get_preference( "Use HTTP HEAD instead of GET" );
if( opt == "yes" ) {
  set_kb_item( name:"NIDS/HTTP/head", value:"yes" );
  warn = TRUE;
}

opt = script_get_preference( "URL encoding" );
if( "none" >< opt ) opt = FALSE;
if( opt ) {
  set_kb_item( name:"NIDS/HTTP/URL_encoding", value:opt );
  whisker_nids = '1';
  warn = TRUE;
}

opt = script_get_preference( "Double slashes" );
if( opt == "yes" ) {
  set_kb_item( name:"NIDS/HTTP/double_slash", value:"yes" );
  warn = TRUE;
}

opt = script_get_preference( "Reverse traversal" );
if( "none" >< opt ) opt = FALSE;
if( opt ) {
  if( opt == "Basic" ) {
    set_kb_item( name:"NIDS/HTTP/reverse_traversal", value:8 );
    warn = TRUE;
  }

  if( opt == "Long URL" ) {
    set_kb_item( name:"NIDS/HTTP/reverse_traversal", value:1000 );
    warn = TRUE;
    whisker_nids = '4';
  }
}

opt = script_get_preference( "Absolute URI type" );
if( opt && "none" >!< opt ) {
  set_kb_item( name:"NIDS/HTTP/absolute_URI/type", value:opt );
  warn = TRUE;
}

opt = script_get_preference( "Absolute URI host" );
if( opt && "none" >!< opt ) {
  set_kb_item( name:"NIDS/HTTP/absolute_URI/host", value:opt );
  warn = TRUE;
}

opt = script_get_preference( "Self-reference directories" );
if( opt == "yes" ) {
  set_kb_item( name:"NIDS/HTTP/self_ref_dir", value:"yes" );
  whisker_nids = '2';
  warn = TRUE;
}

opt = script_get_preference( "Dos/Windows syntax" );
if( opt == "yes" ) {
  set_kb_item( name:"NIDS/HTTP/dos_win_syntax", value:"yes" );
  warn = TRUE;
  whisker_nids = '8';
}

opt = script_get_preference( "Null method" );
if( opt == "yes" ) {
  set_kb_item( name:"NIDS/HTTP/null_method", value:"yes" );
  warn = TRUE;
}

opt = script_get_preference( "TAB separator" );
if( opt == "yes" ) {
  set_kb_item( name:"NIDS/HTTP/tab_separator", value:"yes" );
  warn = TRUE;
  whisker_nids = '6';
}

opt = script_get_preference( "HTTP/0.9 requests" );
if( opt == "yes" ) {
  set_kb_item( name:"NIDS/HTTP/http09", value:"yes" );
  warn = TRUE;
}

opt = script_get_preference( "Premature request ending" );
if( opt == "yes" ) {
  set_kb_item( name:"NIDS/HTTP/premature_request_ending", value:"yes" );
  warn = TRUE;
  whisker_nids = '3';
}

opt = script_get_preference( "CGI.pm semicolon separator" );
if( opt == "yes" ) {
  set_kb_item( name:"NIDS/HTTP/CGIpm_param", value:"yes" );
  warn = TRUE;
}

opt = script_get_preference( "Parameter hiding" );
if( opt == "yes" ) {
  set_kb_item( name:"NIDS/HTTP/param_hiding", value:"yes" );
  warn = TRUE;
  whisker_nids = 5;
}

p = script_get_preference( "Force protocol string : " );
if( p && p != "no" ) {
  set_kb_item( name:"NIDS/HTTP/protocol_string", value:p );
  warn = TRUE;
}

opt = script_get_preference( "Random case sensitivity (Nikto only)" );
if( opt == "yes" ) {
  set_kb_item( name:"NIDS/HTTP/random_case", value: "yes" );
  whisker_nids = 7;
  #warn = TRUE;
  niko_only = TRUE;
}

set_kb_item( name:"/Settings/Whisker/NIDS", value:string( whisker_nids ) );

if( warn ) {
  # Generic key for www_funcs.c of scanner/libs
  set_kb_item( name:"NIDS/HTTP/enabled", value:TRUE );
  log_message( port:0, data:"HTTP NIDS evasion functions are enabled. You may get some false negative results." );
} else {
  if( ! nikto_only )
    log_message( port:0, data:"'Enable HTTP evasion techniques' selected but no technique enabled. Please see the script preferences." );
}

exit( 0 );