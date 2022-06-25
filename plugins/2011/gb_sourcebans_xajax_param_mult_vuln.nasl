###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sourcebans_xajax_param_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# SourceBans 'xajax' Parameter Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802354");
  script_version("$Revision: 11997 $");
  script_bugtraq_id(50948);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-08 12:15:24 +0530 (Thu, 08 Dec 2011)");
  script_name("SourceBans 'xajax' Parameter Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47080");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71669");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71670");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18215/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107589/sourcebans-lfisql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL
  injection attack or directory traversal attacks and gain sensitive information.");
  script_tag(name:"affected", value:"SourceBans versions 1.4.8 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of input passed
  via the parameter 'xajax' to index.php script before being used in SQL queries.
  Which can be exploited to read and delete an arbitrary file.");
  script_tag(name:"solution", value:"Upgrade to version 1.4.9 or later.");
  script_tag(name:"summary", value:"The host is running SourceBan and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.sourcebans.net");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/sourcebans", "/sb", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(">SourceBans" >< res)
  {
    url = dir + "/index.php?xajax=RefreshServer&xajaxargs[]=1'";

    if(http_vuln_check(port:port, url:url, check_header: TRUE,
                       pattern:"You have an error in your SQL syntax;",
                       extra_check:"SQL Query type:"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);