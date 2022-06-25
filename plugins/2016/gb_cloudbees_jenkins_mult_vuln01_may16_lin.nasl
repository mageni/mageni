###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cloudbees_jenkins_mult_vuln01_may16_lin.nasl 12761 2018-12-11 14:32:20Z cfischer $
#
# CloudBees Jenkins Multiple Vulnerabilities-01-May16 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807330");
  script_version("$Revision: 12761 $");
  script_cve_id("CVE-2016-3721", "CVE-2016-3722", "CVE-2016-3723", "CVE-2016-3724",
                "CVE-2016-3725", "CVE-2016-3726", "CVE-2016-3727");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 15:32:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-05-20 13:47:37 +0530 (Fri, 20 May 2016)");
  script_name("CloudBees Jenkins Multiple Vulnerabilities-01-May16 (Linux)");

  script_tag(name:"summary", value:"This host is installed with CloudBees
  Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The XML/JSON API endpoints providing information about installed plugins
    were missing permissions checks, allowing any user with read access to
    Jenkins to determine which plugins and versions were installed.

  - The users with extended read access could access encrypted secrets stored
    directly in the configuration of those items.

  - A missing permissions check allowed any user with access to Jenkins to trigger
    an update of update site metadata. This could be combined with DNS cache
    poisoning to disrupt Jenkins service.

  - The Some Jenkins URLs did not properly validate the redirect URLs, which
    allowed malicious users to create URLs that redirect users to arbitrary
    scheme-relative URLs.

  - The API URL /computer/(master)/api/xml allowed users with the 'extended read'
    permission for the master node to see some global Jenkins configuration,
    including the configuration of the security realm.

  - By changing the freely editable 'full name', malicious users with multiple
    user accounts could prevent other users from logging in, as 'full name' was
    resolved before actual user name to determine which account is currently trying
    to log in.

  - An improper validation of build parameters in Jenkins.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, bypass the protection mechanism,
  gain elevated privileges, bypass intended access restrictions and execute
  arbitrary code.");

  script_tag(name:"affected", value:"CloudBees Jenkins LTS before 1.651.2 on Linux");

  script_tag(name:"solution", value:"Upgrade to CloudBees Jenkins LTS 1.651.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.cloudbees.com/jenkins-security-advisory-2016-05-11");
  script_xref(name:"URL", value:"https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2016-05-11");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/installed", "Host/runs_unixoide");
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

if(version_is_less(version:jenkinVer, test_version:"1.651.2")){
  report = report_fixed_ver(installed_version:jenkinVer, fixed_version:"1.651.2");
  security_message(data:report, port:jenkinPort);
  exit(0);
}

exit(99);