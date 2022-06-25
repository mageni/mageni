###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_servicedesk_mult_vuln_feb15.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# ZOHO ManageEngine ServiceDesk Plus (SDP) Multiple Vulnerabilities - Feb15
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:manageengine:servicedesk_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805138");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2015-1479", "CVE-2015-1480");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-12 17:19:03 +0530 (Thu, 12 Feb 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ZOHO ManageEngine ServiceDesk Plus (SDP) Multiple Vulnerabilities - Feb15");

  script_tag(name:"summary", value:"This host is installed with ZOHO ManageEngine
  ServiceDesk Plus (SDP) and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to the CreateReportTable.jsp
  script not properly sanitizing user-supplied input to the 'site' parameter
  and not properly restricting access to (1) getTicketData action to servlet
  /AJaxServlet or a direct request to (2) swf/flashreport.swf, (3) reports
  /flash/details.jsp, or (4) reports/CreateReportTable.jsp.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated attackers to gain access to ticket information and inject or
  manipulate SQL queries in the back-end database, allowing for the
  manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"ZOHO ManageEngine ServiceDesk Plus (SDP)
  version before 9.0 build 9031");

  script_tag(name:"solution", value:"Upgrade to version 9.0 build 9031 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35890");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130079");
  script_xref(name:"URL", value:"http://www.manageengine.com/products/service-desk/readme-9.0.html");
  script_xref(name:"URL", value:"http://www.rewterz.com/vulnerabilities/manageengine-servicedesk-sql-injection-vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ManageEngine_ServiceDesk_Plus_detect.nasl");
  script_mandatory_keys("ManageEngine/ServiceDeskPlus/installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!appVer = get_app_version(cpe:CPE, port:appPort))
{
  exit(0);
}

versions = split(appVer, sep:"build", keep:0);
major = versions[0];
build = versions[1];

if(major && build)
{
  if(int(major) <= "9.0" && int(build) < "9031")
  {
    report = 'Installed version: ' + appVer + '\n' +
             'Fixed version:     9.0 build 9031\n';
    security_message(data:report, port:appPort);
    exit(0);
  }
}
