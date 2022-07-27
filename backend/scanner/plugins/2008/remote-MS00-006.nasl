##############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-MS00-006.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# This program test for the following vulnerabilities:
# Microsoft Index Server File Information and Path Disclosure Vulnerability (MS00-006)
# Microsoft Index Server 'Malformed Hit-Highlighting' Directory Traversal Vulnerability (MS00-006)
# Microsoft IIS 'idq.dll' Directory Traversal Vulnerability (MS00-006)
# Microsoft Index Server ASP Source Code Disclosure Vulnerability (MS00-006)
#
# remote-MS00-006.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
# Slight modification by Vlatko Kosturjak - Kost <kost@linux.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later,
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

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80007");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_bugtraq_id(950);
  script_cve_id("CVE-2000-0097");
  script_name("Microsoft MS00-06 security check");
  script_category(ACT_ATTACK);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://www.microsoft.com/TechNet/security/bulletin/ms00-006.asp");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"The WebHits ISAPI filter in Microsoft Index Server allows remote attackers to read arbitrary files,
  aka the 'Malformed Hit-Highlighting Argument' vulnerability MS00-06.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# Asp files the plugin will test
pages = make_list( 'default.asp', 'iisstart.asp', 'localstart.asp', 'index.asp' );

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port ) )
  exit( 0 ); # To have a reference to the detection NVT

foreach asp_file( pages ) {

  url = string( "/null.htw?CiWebHitsFile=/" + asp_file + "%20&CiRestriction=none&CiHiliteType=Full" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res ) {
    r = tolower( res );
    if( "Microsoft-IIS" >< r && egrep( pattern:"^HTTP/1.[01] 200", string:r ) && "<html>" >< r ) {
       report = report_vuln_url( port:port, url:url );
       security_message( port:port, data:report );
       exit( 0 );
    }
  }
}

exit( 99 );