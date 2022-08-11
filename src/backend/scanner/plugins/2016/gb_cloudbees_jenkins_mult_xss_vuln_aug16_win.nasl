###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cloudbees_jenkins_mult_xss_vuln_aug16_win.nasl 12761 2018-12-11 14:32:20Z cfischer $
#
# Jenkins Multiple Cross Site Scripting Vulnerabilities August16 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808275");
  script_version("$Revision: 12761 $");
  script_cve_id("CVE-2012-0324", "CVE-2012-0325");
  script_bugtraq_id(52384);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 15:32:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-08-04 13:00:05 +0530 (Thu, 04 Aug 2016)");
  script_name("Jenkins Multiple Cross Site Scripting Vulnerabilities August16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with CloudBees
  Jenkins and is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to multiple
  input validation errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject malicious HTMLs to pages served by Jenkins. This allows
  an attacker to escalate his privileges by hijacking sessions of other users.");

  script_tag(name:"affected", value:"CloudBees Jenkins LTS before 1.424.5 on Windows");

  script_tag(name:"solution", value:"Upgrade to CloudBees Jenkins LTS 1.424.5 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.cloudbees.com/jenkins-security-advisory-2012-03-05");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/installed", "Host/runs_windows");
  script_require_ports("Services/www", 8080);
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

if(version_is_less_equal(version:jenkinVer, test_version:"1.424.3"))
{
  report = report_fixed_ver(installed_version:jenkinVer, fixed_version:"1.424.5");
  security_message(data:report, port:jenkinPort);
  exit(0);
}
