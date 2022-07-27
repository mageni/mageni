###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_truc_xss_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# Tracking Requirements And Use Cases Cross Site Scripting vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800745");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_cve_id("CVE-2010-1095");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Tracking Requirements And Use Cases Cross Site Scripting vulnerability");
  script_xref(name:"URL", value:"http://vul.hackerjournals.com/?p=7357");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0491");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to inject arbitrary
  web script or HTML via the error parameter in the context of an affected site.");
  script_tag(name:"affected", value:"Tracking Requirements and Use Cases (TRUC) version 0.11.0.");
  script_tag(name:"insight", value:"The flaw is due to an input validation error in the
  'login_reset_password_page.php' script when processing data passed via the 'error' parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Tracking Requirements and Use Cases and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

trucPort = get_http_port(default:80);

if(!can_host_php(port:trucPort)){
  exit(0);
}

foreach path (make_list_unique("/", "/truc", "/Truc", cgi_dirs(port:trucPort)))
{

  if(path == "/") path = "";

  rcvRes = http_get_cache(item: path + "/login.php", port:trucPort);
  if("TRUC" >< rcvRes)
  {
    trucVer = eregmatch(pattern:"TRUC ([0-9.]+)", string:rcvRes);
    if(trucVer[1] != NULL)
    {
      if(version_is_equal(version:trucVer[1], test_version:"0.11.0")){
        security_message(port:trucPort);
        exit(0);
      }
    }
  }
}

exit(99);