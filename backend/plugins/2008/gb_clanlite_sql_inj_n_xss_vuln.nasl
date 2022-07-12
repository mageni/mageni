###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clanlite_sql_inj_n_xss_vuln.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# ClanLite SQL Injection and Cross-Site Scripting Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.800145");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5214", "CVE-2008-5215");
  script_bugtraq_id(29156);
  script_name("ClanLite SQL Injection and Cross-Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5595");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/42331");

  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary scripting code or
  SQL commands in the context of an affected application, which allows an
  attacker to steal cookie-based authentication credentials or access and modify data.");
  script_tag(name:"affected", value:"ClanLite Version 2.2006.05.20 and prior.");
  script_tag(name:"insight", value:"The flaws are due to error in service/calendrier.php and
  service/profil.php which are not properly sanitized before being used.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running ClanLite, and is prone to SQL Injection and
  Cross-Site Scripting Vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/clanlite", cgi_dirs(port:port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir + "/service/index_pri.php"), port:port);
  if(!rcvRes)
    continue;

  if("<title>ClanLite" >< rcvRes)
  {
    if(safe_checks())
    {
      clVer = eregmatch(pattern:"ClanLite<.+ V([0-9.]+)", string:rcvRes);
      if(clVer[1] != NULL) {
        if(version_is_less_equal(version:clVer[1], test_version:"2.2006.05.20")){
          security_message(port:port);
        }
      }
      exit(0);
    }

    url = string(dir + "/service/calendrier.php?mois=6&annee='><script>alert(document.cookie)</script>");
    sndReq = http_get(item:url, port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);
    if(!rcvRes)
      continue;

    if("<script>alert(document.cookie)</script>" >< rcvRes){
      security_message(port:port);
    }
    exit(0);
  }
}

exit(99);