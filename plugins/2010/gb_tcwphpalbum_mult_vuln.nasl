###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tcwphpalbum_mult_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# TCW PHP Album 'album' Parameter Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801231");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)");
  script_cve_id("CVE-2010-2714", "CVE-2010-2715");
  script_bugtraq_id(41382);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("TCW PHP Album 'album' Parameter Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60078");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60079");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1696");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14203");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to run HTML or
  JavaScript code in the context of the affected site, or exploit latent
  vulnerabilities in the underlying database.");
  script_tag(name:"affected", value:"TCW PHP Album Version 1.0");
  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input passed via the 'album' parameter to 'index.php', which allows attackers
  to perform cross-site scripting, SQL-injection, and HTML-Injection attacks.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running TCW PHP Album and is prone to multiple input
  validation vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!can_host_php(port:port)) exit(0);

foreach dir (make_list_unique("/phpalbum", "/tcwphpalbum", "/", cgi_dirs(port:port) ))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir,"/index.php"),  port:port);

  if("<TITLE>My Pics</TITLE>" >< res && "tcwphpalbum" >< res)
  {
    if(http_vuln_check(port:port, url:string(dir,"/index.php?album=<script>",
                       "alert('OpenVAS-XSS-Test')</script>"),
                       pattern:"<script>alert\('OpenVAS-XSS-Test'\)</script>",
                       check_header:TRUE))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
