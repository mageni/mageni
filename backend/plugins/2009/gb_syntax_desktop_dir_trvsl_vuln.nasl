##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_syntax_desktop_dir_trvsl_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Syntax Desktop Directory Traversal Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800234");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(33601);
  script_cve_id("CVE-2009-0448");
  script_name("Syntax Desktop Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7977");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"affected", value:"Syntax Desktop 2.7 and prior");
  script_tag(name:"insight", value:"This flaw is due to error in file 'preview.php' in 'synTarget'
  parameter which lets the attacker to gain information through directory
  traversal queries.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Syntax Desktop and is prone to Directory
  Traversal Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker gain sensitive information
  about the remote system directories where syntax desktop runs.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

synPort = get_http_port(default:80);

if(!can_host_php(port:synPort)){
  exit(0);
}

files = traversal_files();

foreach path(make_list_unique("/", cgi_dirs(port:synPort))) {

  if(path == "/") path = "";

  response = http_get_cache(item: path + "/index.php", port:synPort);

  if("Syntax Desktop" >< response) {

    foreach file ( keys( files ) ) {

      url = path + "/admin/modules/aa/preview.php?synTarget=../../../../../../../../../" + files[file] + "%00";
      if( http_vuln_check( port:synPort, url:url, pattern:file  ) ) {
        report = report_vuln_url(port:synPort, url:url);
        security_message(port:synPort, data:report);
        exit(0);
      }
    }
  }
}

exit(99);