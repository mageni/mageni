###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cloudbees_jenkins_mult_vuln02_may16_lin.nasl 12761 2018-12-11 14:32:20Z cfischer $
#
# CloudBees Jenkins Multiple Vulnerabilities-02-May16 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807332");
  script_version("$Revision: 12761 $");
  script_cve_id("CVE-2016-0788", "CVE-2016-0789", "CVE-2016-0790", "CVE-2016-0791",
                "CVE-2016-0792");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 15:32:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-05-20 16:08:55 +0530 (Fri, 20 May 2016)");
  script_name("CloudBees Jenkins Multiple Vulnerabilities-02-May16 (Linux)");

  script_tag(name:"summary", value:"This host is installed with CloudBees
  Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The verification of user-provided API tokens with the expected value did
    not use a constant-time comparison algorithm, potentially allowing
    attackers to use statistical methods to determine valid API tokens using
    brute-force methods.

  - The verification of user-provided CSRF crumbs with the expected value did
    not use a constant-time comparison algorithm, potentially allowing attackers
    to use statistical methods to determine valid CSRF crumbs using brute-force
    methods.

  - The Jenkins has several API endpoints that allow low-privilege users to POST
    XML files that then get deserialized by Jenkins. Maliciously crafted XML
    files sent to these API endpoints could result in arbitrary code execution.

  - An HTTP response splitting vulnerability in the CLI command documentation
    allowed attackers to craft Jenkins URLs that serve malicious content.

  - The Jenkins remoting module allowed unauthenticated remote attackers to open
    a JRMP listener on the server hosting the Jenkins master process, which
    allowed arbitrary code execution.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, bypass the protection mechanism,
  gain elevated privileges, bypass intended access restrictions and execute
  arbitrary code.");

  script_tag(name:"affected", value:"CloudBees Jenkins LTS before 1.642.2 on Linux");

  script_tag(name:"solution", value:"Upgrade to CloudBees Jenkins LTS 1.642.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2016-02-24");
  script_xref(name:"URL", value:"https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"https://www.cloudbees.com");
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

if(version_is_less(version:jenkinVer, test_version:"1.642.2")){
  report = report_fixed_ver(installed_version:jenkinVer, fixed_version:"1.642.2");
  security_message(data:report, port:jenkinPort);
  exit(0);
}

exit(99);