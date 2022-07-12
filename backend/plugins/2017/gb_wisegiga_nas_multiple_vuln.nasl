###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wisegiga_nas_multiple_vuln.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# WiseGiga NAS Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/h:wisegiga:nas";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811336");
  script_version("$Revision: 14175 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-09-12 13:20:40 +0530 (Tue, 12 Sep 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("WiseGiga NAS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is running WiseGiga NAS device(s)
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST with
  default credentials and check whether it is able to login or not.");

  script_tag(name:"insight", value:"- An user controlled input is not sufficiently sanitized and can be exploit
    by an attacker to get sensitive information.

  - By sending GET request to the following URI's with 'filename=' as a
    parameter, an attacker can trigger the vulnerabilities:

  - /webfolder/download_file1.php

  - down_data.php

  - download_file.php

  - mobile/download_file1.php

  - By sending GET request to '/mobile/download_file2.php' an attacker can get
    sensitive information.

  - By sending a GET request to 'root_exec_cmd()' with user controlled '$cmd'
    variable input an attacker can execute arbitrary commands.

  - Accessing 'webfolder/config/config.php' will disclose the PHP configuration.

  - Default accounts:

  - Username: guest

  - Password: guest09#$");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to bypass authentication mechanism and perform
  unauthorized actions and execute arbitrary commands.");

  script_tag(name:"affected", value:"WiseGiga NAS devices.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/42651/");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3402");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wisegiga_nas_detect.nasl");
  script_mandatory_keys("WiseGiga_NAS/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

include("misc_func.inc");

if(!netPort = get_app_port(cpe:CPE)){
  exit(0);
}

url = "/webfolder/login_check.php";

postdata = "id=guest&passwd=guest09%23%24&remember_check=0&sel_lang=en: undefined";

req = http_post_req( port:netPort, url:url, data:postdata,
                     accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                     add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded",
                                               "Upgrade-Insecure-Requests", "1"));
rcvRes = http_send_recv( port:netPort, data:req );

if(rcvRes =~ "HTTP/1.. 200" && "location.href='main.php';" >< rcvRes &&
   '<script language="JavaScript">' >< rcvRes &&
   "Set-Cookie: PASSWORD=guest" >< rcvRes && "Set-Cookie: org_name=guest" >< rcvRes)
{
  report = "It was possible to log in with the default username/password: 'guest/guest09#$'";
  security_message( port:netPort, data:report);
  exit(0);
}

exit(0);
