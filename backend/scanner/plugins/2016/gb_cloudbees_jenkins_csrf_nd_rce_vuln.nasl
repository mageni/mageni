###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cloudbees_jenkins_csrf_nd_rce_vuln.nasl 12761 2018-12-11 14:32:20Z cfischer $
#
# Jenkins CSRF And Code Execution Vulnerabilities Aug16
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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809025");
  script_version("$Revision: 12761 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 15:32:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-08-31 12:50:25 +0530 (Wed, 31 Aug 2016)");
  script_name("Jenkins CSRF And Code Execution Vulnerabilities Aug16");

  script_tag(name:"summary", value:"This host is installed with CloudBees
  Jenkins and is prone to cross-site request forgery and code execution
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an improper session
  management for most request.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to hijack the authentication of users for most request and to
  change specific settings or even execute code on os.");

  script_tag(name:"affected", value:"CloudBees Jenkins version 1.626");

  script_tag(name:"solution", value:"Updates are available to fix this issue.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37999");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl");
  script_mandatory_keys("jenkins/installed");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"https://www.cloudbees.com/cloudbees-security-advisory-2017-02-01");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!jenkinPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!jenkinVer = get_app_version(cpe:CPE, port:jenkinPort)){
  exit(0);
}

if(version_is_equal(version:jenkinVer, test_version:"1.626"))
{
  report = report_fixed_ver(installed_version:jenkinVer, fixed_version:"See Vendor");
  security_message(data:report, port:jenkinPort);
  exit(0);
}
