###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_myserver_remote_dos_vuln.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# MyServer Remote Denial of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800306");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5160");
  script_bugtraq_id(27981);
  script_name("MyServer Remote Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27981");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("MyServer/banner");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful attacks will lead to denial of service to legitimate users.");
  script_tag(name:"affected", value:"MyServer MyServer version 0.8.11 and prior on all running platforms.");
  script_tag(name:"insight", value:"The flaw is due to multiple invalid requests in HTTP GET, DELETE,
  OPTIONS, and possibly other methods. These requests are related to '204 No Content error'.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to MyServer version 0.9 or later.");
  script_tag(name:"summary", value:"This host is running MyServer and is prone to denial of service
  vulnerability.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner) exit(0);

mysvrVer = eregmatch(pattern:"MyServer ([0-9.]+)", string:banner);
if(mysvrVer[1] != NULL)
{
  # MyServer Version 0.8.11 and prior
  if(version_is_less_equal(version:mysvrVer[1], test_version:"0.8.11")){
    security_message(port);
  }
}
