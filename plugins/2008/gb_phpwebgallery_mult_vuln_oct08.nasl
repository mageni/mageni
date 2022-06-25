###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpwebgallery_mult_vuln_oct08.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# Multiple XSS Vulnerabilities in PHPWebGallery - Oct08
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800115");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-21 16:25:40 +0200 (Tue, 21 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4591", "CVE-2008-4702");
  script_name("Multiple XSS Vulnerabilities in PHPWebGallery - Oct08");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6425");

  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary HTML or scripting
  code in the security context of an affected web page.");
  script_tag(name:"affected", value:"PHPWebGallery Version 1.3.4 and prior on all running platform.");
  script_tag(name:"insight", value:"The flaws are due to improper validation of input data to parameters
  in isadmin.inc.php and init.inc.php file, which allow remote attackers to
  inject arbitrary web script via lang[access_forbiden], lang[ident_title],
  user[language] and user[template] parameters.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running PHPWebGallery which is prone to multiple
  XSS and script inclusion Vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

dirs = make_list_unique("/phpwebgallery", cgi_dirs(port:port));
foreach dir (dirs)
{

  if( dir == "/" ) dir = "";

  url = dir + "/category.php";
  rcvRes = http_get_cache(item:url, port:port);
  if(!rcvRes)
    continue;

  if(rcvRes =~ "Powered by.+PhpWebGallery")
  {
    if(safe_checks())
    {
      rcvRes = eregmatch(pattern:"PhpWebGallery.+ ([0-9.]+)", string:rcvRes);
      if(rcvRes != NULL)
      {
        if(version_is_less_equal(version:rcvRes[1], test_version:"1.3.4")){
          security_message(port);
        }
      }
      exit(0);
    }
    url = dir + "/admin/include/isadmin.inc.php?lang[access_forbiden]=<script>alert(document.cookie);</script>";
    sndReq = http_get(item:url, port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);
    if(!rcvRes)
      continue;

    if("<script>alert(document.cookie);</script>" >< rcvRes){
      security_message(port);
    }
    exit(0);
  }
}

exit(99);