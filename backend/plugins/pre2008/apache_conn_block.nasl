# OpenVAS Vulnerability Test
# $Id: apache_conn_block.nasl 14336 2019-03-19 14:53:10Z mmartin $
# Description: Apache Connection Blocking Denial of Service
#
# Authors:
# Original script written by Tenable Network Security
# Modified by Scott Shebby scotts@scanalert.com
# OS check by George Theall
#
# Copyright:
# Copyright (C) 2004 Scott Shebby
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12280");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9921);
  script_cve_id("CVE-2004-0174");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Apache Connection Blocking Denial of Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Scott Shebby");
  script_family("Denial of Service");
  script_dependencies("http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/apache", "Host/runs_unixoide");

  script_tag(name:"solution", value:"Upgrade to Apache 2.0.49 or 1.3.31.");
  script_tag(name:"summary", value:"The remote web server appears to be running a version of
Apache that is less that 2.0.49 or 1.3.31.

These versions are vulnerable to a denial of service attack where a remote
attacker can block new connections to the server by connecting to a listening
socket on a rarely accessed port.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner)exit(0);

serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-8])", string:serv))
 {
   security_message(port);
   exit(0);
 }
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.|3\.([0-9][^0-9]|[0-2][0-9]|30)))", string:serv))
 {
   security_message(port);
   exit(0);
 }
