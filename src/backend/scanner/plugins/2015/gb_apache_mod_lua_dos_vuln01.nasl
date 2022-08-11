###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mod_lua_dos_vuln01.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# Apache HTTP Server Mod_Lua Denial of service Vulnerability -01 May15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805616");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2015-0228");
  script_bugtraq_id(73041);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-18 13:29:48 +0530 (Mon, 18 May 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Only vulnerable if mod_lua is enabled
  script_name("Apache HTTP Server Mod_Lua Denial of service Vulnerability -01 May15");

  script_tag(name:"summary", value:"This host is installed with Apache HTTP Server
  and is prone to denial of service  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to vulnerability in
  lua_websocket_read function in lua_request.c in the mod_lua module.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attackers to cause a denial of service via some crafted dimension.");

  script_tag(name:"affected", value:"Apache HTTP Server versions through
  2.4.12.");

  script_tag(name:"solution", value:"Upgrade to version 2.4.13 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15428");
  script_xref(name:"URL", value:"http://svn.apache.org/repos/asf/httpd/httpd/branches/2.4.x/CHANGES");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl");
  script_mandatory_keys("apache/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.apache.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!httpd_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!httpd_ver = get_app_version(cpe:CPE, port:httpd_port)){
  exit(0);
}

if(version_is_less_equal(version:httpd_ver, test_version:"2.4.12"))
{
  report = 'Installed version: ' + httpd_ver + '\n' +
           'Fixed version:     ' + "2.4.13" + '\n';
  security_message(data:report, port:httpd_port);
  exit(0);
}
