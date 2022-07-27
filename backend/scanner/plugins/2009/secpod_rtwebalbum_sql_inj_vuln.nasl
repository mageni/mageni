###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rtwebalbum_sql_inj_vuln.nasl 14335 2019-03-19 14:46:57Z asteins $
#
# RTWebalbum SQL Injection Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900373");
  script_version("$Revision: 14335 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:46:57 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-06-23 10:30:45 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1910");
  script_bugtraq_id(34888);
  script_name("RTWebalbum SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35022");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50406");
  script_xref(name:"URL", value:"http://rtwebalbum.svn.sourceforge.net/viewvc/rtwebalbum");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to manipulate SQL queries by
  injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"RTWebalbum versions prior to 1.0.574");
  script_tag(name:"insight", value:"Input passed to the 'AlbumId' parameter in index.php is not properly sanitised
  before being used in SQL queries");
  script_tag(name:"solution", value:"Upgrade to RTWebalbum version 1.0.574.");
  script_tag(name:"summary", value:"This host is running RTWebalbum and is prone to an SQL Injection
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

rtwebPort = get_http_port(default:80);

if(!can_host_php(port:rtwebPort)){
  exit(0);
}

foreach rtwebDir (make_list_unique("/rtwebalbum", cgi_dirs(port:rtwebPort)))
{

  if(rtwebDir == "/") rtwebDir = "";

  rcvRes = http_get_cache(item: rtwebDir + "/admin.php", port:rtwebPort);

  if("rtwebalbum" >!< rcvRes)
  {
    rcvRes = http_get_cache(item: rtwebDir + "/index.php", port:rtwebPort);
  }

  if(egrep(pattern:"<a\ href=?[^?]+:\/\/sourceforge.net\/projects\/rtwebalbum",
     string:rcvRes) && egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    # Attack for SQL Injection with AlbumID is 1
    sndReq = http_get(item: rtwebDir + "/index.php?AlbumId=1+AND+1=1#",
                      port:rtwebPort);
    rcvRes = http_keepalive_send_recv(port:rtwebPort, data:sndReq);

    #Exploit for 'True' Condition
    if(rcvRes =~ "<div\ id=.?descrp.?>[^<]" ||
       rcvRes =~ "<div\ id=.?descrp2.?>[^<]")
    {
      security_message(port:rtwebPort, data:"The target host was found to be vulnerable.");
      exit(0);
    }
  }
}

exit(99);
