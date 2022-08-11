###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ldap_account_manager_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# LDAP Account Manager Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Modified in accordance to Latest format, functions and output
#  - By Rajat Mishra <rajatm@secpod.com> On 2018-03-26
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103158");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-05-03 13:15:04 +0200 (Tue, 03 May 2011)");
  script_name("LDAP Account Manager Detection");

  script_tag(name:"summary", value:"This host is running LDAP Account Manager
, a webfrontend for managing entries (e.g. users, groups, DHCP settings) stored
  in an LDAP directory.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8181);
  script_mandatory_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port(default:8181);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/ldap", "/ldap-account-manager", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = string(dir, "/templates/login.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( !buf ) continue;

 if("<title>LDAP Account Manager</title>" >< buf && "LAM configuration" >< buf)
 {
    lamvers = string("unknown");
    version  = eregmatch(string: buf, pattern: "LDAP Account Manager - ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       lamvers = chomp(version[1]);
    }

    set_kb_item(name:"www/" + port + "/ldap_account_manager", value:string(lamvers," under ",install));
    set_kb_item( name:"ldap_account_manager/installed", value:TRUE);

    cpe = build_cpe(value:lamvers, exp:"^([0-9.]+)", base:"cpe:/a:ldap_account_manager:ldap_account_manager:");
    if(isnull(cpe))
      cpe = "cpe:/a:ldap_account_manager:ldap_account_manager";

    register_product(cpe: cpe, location:install , port:port);
    log_message(data: build_detection_report(app: "LDAP Account Manager",
                                               version: lamvers,
                                               install: install,
                                                   cpe: cpe,
                                             concluded: lamvers),
                                             port: port);
    exit(0);
  }
}

exit(0);
