###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_geovision_ip_camera_mult_vuln.nasl 8745 2018-02-09 14:30:40Z santu $
#
# Geovision Inc. IP Camera Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/h:geovision:geovisionip_camera";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812759");
  script_version("$Revision: 8745 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-09 15:30:40 +0100 (Fri, 09 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-08 13:00:22 +0530 (Thu, 08 Feb 2018)");
  script_name("Geovision Inc. IP Camera Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is running Geovision Inc. IP Camera 
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to access sensitive information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An improper access control on multiple pages 'UserCreat.cgi', 'LangSetting.cgi',
    'sdk_fw_update.cgi' and 'sdk_config_set.cgi'.

  - An improper input validation for 'sdk_fw_check.cgi' during upload.

  - Multiple input validation errors in several '.cgi' scripts.

  - An improper access control for GET and PUT operations for pages under 
    '/PSIA' directory.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to execute arbitrary commands, cause information disclosure and 
  cause Stack Overflow condition.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Geovision Inc. IP Camera.");

  script_tag(name:"solution", value:"No solution or patch is available as of
  8th Feb, 2018. Information regarding this issue will be updated once solution
  details are available. For updates refer to http://www.geovision.com.tw/");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/43983");
  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/43982");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_geovision_ip_camera_remote_detect.nasl");
  script_mandatory_keys("GeoVisionIP/Camera/Detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

gePort = 0;
report = "";
url = "";

if(!gePort = get_app_port(cpe:CPE)){
  exit(0);
}

url = '/PSIA/indexr';
if(http_vuln_check(port:gePort, url:url , pattern: '<ResourceList.*version=.*>', 
                   extra_check:make_list('<type>resource</type>', '<version>[0-9.]+</version>', 
                                         '<name>[a-ZA-z]+</name>'), check_header: TRUE))
{
  report = report_vuln_url(port:gePort, url:url);
  security_message(port:gePort, data:report);
  exit(0);
}
exit(0);
