###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jenkins_20170426_win.nasl 12761 2018-12-11 14:32:20Z cfischer $
#
# Jenkins Security Advisory Apr17 - Multiple Vulnerabilities (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107157");
  script_version("$Revision: 12761 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 15:32:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-04-28 12:09:09 +0200 (Fri, 28 Apr 2017)");
  script_cve_id("CVE-2017-1000353", "CVE-2017-1000354", "CVE-2017-1000355", "CVE-2017-1000356");
  script_bugtraq_id(98056);

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Jenkins Security Advisory Apr17 - Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"Multiple Cross-Site Request Forgery vulnerabilities in Jenkins allow malicious users to perform several administrative actions by tricking a victim into opening a web page.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to::

  - multiple Cross-Site Request Forgery vulnerabilities.

  - the storage of the encrypted user name in a cache file which is used to authenticate further commands.

  - XStream library which allow anyone able to provide XML to Jenkins for processing using XStream to crash the Java process.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to:

  - perform several administrative actions by tricking a victim into opening a web page.execute arbitrary code in the context of the affected application.

  - to transfer a serialized Java SignedObject object to the remoting-based Jenkins CLI, that would be deserialized using a new ObjectInputStream, bypassing the existing blacklist-based protection mechanism.

  - impersonate any other Jenkins user on the same instance.

  - crash the Java process.");

  script_tag(name:"affected", value:"The following products are vulnerable:
    Jenkins LTS 2.46.1 and prior, Jenkins 2.56 and prior.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 2.57,
    Jenkins LTS users should update to 2.46.2");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98056");
  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2017-04-26/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/installed", "Host/runs_windows");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port)){
  exit(0);
}

if(version_is_less(version:Ver, test_version:"2.46.2")){
  vuln = TRUE;
  fix = "2.46.2";
}

if(version_in_range(version:Ver, test_version:"2.47", test_version2:"2.57")){
  vuln = TRUE;
  fix = "2.57";
}

if(vuln){
  report = report_fixed_ver(installed_version:Ver, fixed_version:fix);
  security_message(port:Port, data:report);
  exit(0);
}

exit(99);
