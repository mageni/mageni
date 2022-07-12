###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_dgn2200_n300_mult_vuln.nasl 35234 2014-02-18 11:02:48Z Feb$
#
# NetGear DGN2200 N300 Wireless Router Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804099");
  script_version("$Revision: 12008 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:12:11 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-18 11:02:48 +0530 (Tue, 18 Feb 2014)");
  script_name("NetGear DGN2200 N300 Wireless Router Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("NETGEAR_DGN/banner");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31617");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125184");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Feb/104");

  script_tag(name:"summary", value:"This host has NetGear DGN2200 N300 Wireless Router and is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request to restricted page and check whether it is able to
  access or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - FTP Server not properly sanitizing user input, specifically absolute paths.

  - Program not allowing users to completely disable the Wi-Fi Protected Setup
  (WPS) functionality.

  - Web interface attempting to find new firmware on an FTP server every time an
  administrator logs in.

  - UPnP Interface as HTTP requests to /Public_UPNP_C3 do not require multiple
  steps, explicit confirmation, or a unique token when performing certain
  sensitive actions.

  - Input passed via the 'ping_IPAddr' parameter is not properly sanitized upon
  submission to the /ping.cgi script.

  - Input passed via the 'hostname' parameter is not properly sanitized upon
  submission to the /dnslookup.cgi script.

  - Program storing password information in plaintext in /etc/passwd.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary commands,
  gain access to arbitrary files, and manipulate the device's settings.");

  script_tag(name:"affected", value:"NetGear DGN2200 N300 Wireless Router Firmware Version 1.0.0.36-7.0.37");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:8080);
banner = get_http_banner(port:http_port);

if(!banner || 'Basic realm="NETGEAR DGN' >!< banner) exit(0);

url = '/currentsetting.htm';

if(http_vuln_check(port:http_port, url:url, pattern:"Firmware", extra_check: make_list("RegionTag", "Region", "Model", "InternetConnectionStatus", "ParentalControlSupported"))) {
  report = report_vuln_url(url:url, port:http_port);
  security_message(data:report, port:http_port);
}

exit(0);