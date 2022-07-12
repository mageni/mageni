###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_projectsend_mult_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# ProjectSend Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:projectsend:projectsend";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807550");
  script_version("$Revision: 12149 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-19 11:50:28 +0530 (Tue, 19 Apr 2016)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("ProjectSend Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host has ProjectSend web application
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and
  check whether it is able read the sensitive information");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Insufficient validation of user supplied input via parameters 'status',
    'files' in manage-files.php script, 'selected_clients', 'status' in
    'clients.php' script, 'file' in process-zip-download.php script and 'action'
    in home-log.php script.

  - The page actions.log.export.php, users.php, users-add.php, home.php,
    edit-file.php and process-zip-download.php scripts fails to perform
    authentication checks.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to protected resources and to execute arbitrary SQL
  commands via different vectors..");

  script_tag(name:"affected", value:"ProjectSend r582 and probably prior.");

  script_tag(name:"solution", value:"Fixes are available via the references. Update to the latest version.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39385");
  script_xref(name:"URL", value:"https://www.wearesegment.com/research/Projectsend_multiple_vulnerabilities");
  script_xref(name:"URL", value:"https://github.com/ignacionelson/ProjectSend/pull/82");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_projectsend_remote_detect.nasl");
  script_mandatory_keys("ProjectSend/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.projectsend.org");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!pjtPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:pjtPort)){
  exit( 0 );
}

if(dir == "/"){
  dir = "";
}

url = dir + "/includes/actions.log.export.php";

if(http_vuln_check(port:pjtPort, url:url, check_header:TRUE,
   pattern:"ProjectSend was installed",
   extra_check:"Content-Disposition: attachment; filename="))
{
  report = report_vuln_url( port:pjtPort, url:url );
  security_message(port:pjtPort, data:report);
  exit(0);
}
