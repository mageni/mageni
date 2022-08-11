###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_jenkins_groovy_console.nasl 12761 2018-12-11 14:32:20Z cfischer $
#
# Jenkins CI Groovy Console accessible
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111002");
  script_version("$Revision: 12761 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 15:32:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2015-03-02 12:00:00 +0100 (Mon, 02 Mar 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Jenkins CI Groovy Console accessible");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("sw_jenkins_detect.nasl");
  script_require_keys("jenkins/installed");

  script_tag(name:"summary", value:"The script sends a HTTP request to the
  server and checks if the Groovy Console is unprotected.");
  script_tag(name:"impact", value:"The Groovy Console allows an attacker to execute
  operating system commands with the permissions of the user running the service.");
  script_tag(name:"vuldetect", value:"Connect to port 8080 and check the response.");
  script_tag(name:"solution", value:"Protect the access to the Groovy Console by
  configuring user accounts. Please see the reference for more information.");

  script_xref(name:"URL", value:"https://wiki.jenkins-ci.org/display/JENKINS/Securing+Jenkins");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/script";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Script Console" >< buf && "Groovy script" >< buf )
{
  security_message( port:port );
  exit ( 0 );
}

exit ( 99 );
