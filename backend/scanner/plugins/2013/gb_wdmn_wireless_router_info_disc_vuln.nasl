###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wdmn_wireless_router_info_disc_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Western Digital My Net Devices Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803731");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-5006");
  script_bugtraq_id(61361);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-05 16:18:11 +0530 (Mon, 05 Aug 2013)");
  script_name("Western Digital My Net Devices Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running Western Digital My Net Router and is prone to information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP request and check whether it is able to read the
  password or not.");

  script_tag(name:"solution", value:"Upgrade to version 1.07.16, for the My Net N900 and My Net N900.
  For My Net N600 and My Net N750 solution is to revert to the earlier firmware of 1.01.04 or 1.01.20,
  or disable remote administrative access.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"The issue is due to the device storing the admin password in clear text in the
  main_internet.php source code page as the value for 'var pass'.");

  script_tag(name:"affected", value:"Western Digital My Net N600 1.03, 1.04,

  Western Digital My Net N750 1.03, 1.04,

  Western Digital My Net N900 1.05, 1.06 and

  Western Digital My Net N900C 1.05, 1.06");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain access to credential
  information.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Aug/10");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/85903");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/527433");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2013-07/0146.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("MyNetN679/banner");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"http://www.wdc.com/en");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port: port);
if(banner && banner =~ "MyNetN[6|7|9]")
{
  req = http_get(item: "/main_internet.php", port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  if(">WESTERN DIGITAL" >< res && "WIRELESS ROUTER" >< res
     && res =~ 'var pass=".*";' )
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
