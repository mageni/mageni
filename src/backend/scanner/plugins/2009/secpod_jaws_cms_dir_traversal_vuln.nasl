##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_jaws_cms_dir_traversal_vuln.nasl 14332 2019-03-19 14:22:43Z asteins $
#
# Jaws CMS Directory Traversal Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900460");
  script_version("$Revision: 14332 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:22:43 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_bugtraq_id(33607);
  script_cve_id("CVE-2009-0645");
  script_name("Jaws CMS Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7976");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48476");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"affected", value:"Jaws CMS 0.8.8 and prior");
  script_tag(name:"insight", value:"This flaw is due to an error in file 'index.php' in 'language'
  parameter which lets the attacker execute local file inclusion attacks.");
  script_tag(name:"solution", value:"Upgrade to the latest version 0.8.9.");
  script_tag(name:"summary", value:"This host is running Jaws CMS and is prone to a Directory
  Traversal Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute local file inclusion
  attacks and gain sensitive information about the remote system directories where Jaws CMS runs.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("version_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

jawsPort = get_http_port(default:80);

if(!can_host_php(port:jawsPort)){
  exit(0);
}

foreach path(make_list_unique("/", cgi_dirs(port:jawsPort)))
{

  if(path == "/") path = "";

  request = http_get(item: path + "/jaws/index.php", port:jawsPort);
  response = http_keepalive_send_recv(port:jawsPort, data:request);

  if(response == NULL){
    exit(0);
  }
  if("Jaws" >< response)
  {
    version = eregmatch(pattern:"Jaws ([0-9.]+)", string:response);
    if(version[1] != NULL)
    {
      if(version_is_less_equal(version:version[1], test_version:"0.8.8"))
      {
        security_message(port:jawsPort, data:"The target host was found to be vulnerable.");
        exit(0);
      }
    }
  }
}

exit(99);
