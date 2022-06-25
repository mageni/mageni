###############################################################################
# OpenVAS Vulnerability Test
# $Id: DDI_IIS_dotNet_Trace.nasl 10826 2018-08-08 07:30:42Z cfischer $
#
# IIS ASP.NET Application Trace Enabled
#
# Authors:
# H D Moore
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
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

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10993");
  script_version("$Revision: 10826 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 09:30:42 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("IIS ASP.NET Application Trace Enabled");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");
  script_family("Web application abuses");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"https://msdn.microsoft.com/en-us/library/ms972204.aspx");

  script_tag(name:"solution", value:"Set <trace enabled=false> in web.config");

  script_tag(name:"summary", value:"The ASP.NET web application running in the root
  directory of this web server has application tracing enabled.");

  script_tag(name:"impact", value:"This could allow an attacker to view the last 50
  web requests made to this server, including sensitive information like Session ID
  values and the physical path to the requested file.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = "/trace.axd";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "Application Trace" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );