###############################################################################
# OpenVAS Vulnerability Test
#
# SolarWinds Storage Resource Monitor Multiple SQL injection vulnerabilities
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:solarwinds:storage_resource_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809427");
  script_version("2019-05-03T13:51:56+0000");
  script_cve_id("CVE-2016-4350");
  script_bugtraq_id(89557);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 13:51:56 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-10-03 15:36:59 +0530 (Mon, 03 Oct 2016)");
  script_name("SolarWinds Storage Resource Monitor Multiple SQL injection vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with SolarWinds Storage
  Resource Monitor and is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to Web Services
  web server does not validate state parameter properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary SQL commands.");

  script_tag(name:"affected", value:"SolarWinds Storage Resource Monitor
  before 6.2.3");

  script_tag(name:"solution", value:"Upgrade to SolarWinds Storage Resource
  Monitor 6.2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_probe");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-253");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-259");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-262");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_solarwinds_storage_resource_monitor_detect.nasl");
  script_mandatory_keys("storage_manager/Installed");
  script_require_ports("Services/www", 9000);

  script_xref(name:"URL", value:"http://www.solarwinds.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!srmport = get_app_port(cpe:CPE)){
  exit(0);
}

host = get_host_name();

data =  "loginState=checkLogin&loginName=admin&password=";


req = http_post_req( port:srmport,
                     url:'/LoginServlet',
                     data:data,
                     accept_header:'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                     add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );

buf = http_keepalive_send_recv( port:srmport, data:req, bodyonly:FALSE );

if(buf =~ "HTTP/1\.. 200" && "SolarWinds - Storage Manager" ><  buf)
{
  cookie = eregmatch( pattern:"Set-Cookie: ([0-9a-zA-Z=]+);", string:buf );
  if(!cookie[1]){
    exit(0);
  }

  ## Login with defaoult username and try the SQL injection.
  url = "/DuplicateFilesServlet?fileName=%27SQL-INJECTION-TEST";

  if(http_vuln_check(port:srmport, url:url, check_header:TRUE, cookie: cookie[1],
                   pattern:"SQL-INJECTION-TEST",
                   extra_check:make_list(">Enterprise Report<", ">Storage Manager<")))
  {
    report = report_vuln_url(port:srmport, url:url);
    security_message(port:srmport, data:report);
    exit(0);
  }
}
