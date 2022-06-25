##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_av_arcade_sql_inj_vuln.nasl 11396 2018-09-14 16:36:30Z cfischer $
#
# AV Arcade 'ava_code' Cookie Parameter SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801396");
  script_version("$Revision: 11396 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-14 18:36:30 +0200 (Fri, 14 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_cve_id("CVE-2010-2933");
  script_bugtraq_id(42023);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AV Arcade 'ava_code' Cookie Parameter SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60799");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14494/");

  script_tag(name:"insight", value:"The flaws are due to an improper validation of authentication
  cookies in the 'index.php' script, when processing the 'ava_code' cookie parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running AV Arcade and is prone SQL injection
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security
  restrictions and gain unauthorized administrative access to the vulnerable application.");

  script_tag(name:"affected", value:"AV Scripts AV Arcade version 3.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/avarcade", "/avarcade/upload" , cgi_dirs(port:port))){

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(">AV Arcade" >< res && ">AV Scripts</" >< res){

    req = http_get(item: dir + "/admin/stats.php", port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(">AV Arcade" >< res){
      acVer = eregmatch(pattern:"> ([0-9.]+)", string:res);
      if(acVer[1]){
        if(version_is_equal(version:acVer[1], test_version:"3.0")){
          report = report_fixed_ver(installed_version:acVer[1], fixed_version:"WillNotFix");
          security_message(port:port, data:report);
          exit(0);
        }
      }
    }
  }
}

exit(99);