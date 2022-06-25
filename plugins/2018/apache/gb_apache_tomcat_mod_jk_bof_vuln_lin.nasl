###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat JK Connector Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:mod_jk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812787");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2016-6808");
  script_bugtraq_id(93429);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-27 10:49:53 +0530 (Tue, 27 Feb 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Apache Tomcat JK Connector Buffer Overflow Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  JK connector and is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as IIS/ISAPI specific code
  implements special handling when a virtual host is present. The virtual host
  name and the URI are concatenated to create a virtual host mapping rule.
  The length checks prior to writing to the target buffer for this rule did not
  take account of the length of the virtual host name.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow
  remote attackers to execute arbitrary code in the context of the user running the
  application. Failed exploit attempts will likely result in denial-of-service
  conditions.");

  script_tag(name:"affected", value:"Apache Tomcat JK Connector 1.2.0 through 1.2.41 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat JK Connector version 1.2.42 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-jk.html");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/139071");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_mod_jk_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache_modjk/detected", "Host/runs_unixoide");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!tomPort = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:tomPort, exit_no_version:TRUE)) exit(0);
appVer = infos['version'];
path = infos['location'];

if(version_in_range(version:appVer, test_version: "1.2.0", test_version2: "1.2.41")) {
  report = report_fixed_ver(installed_version:appVer, fixed_version:"1.2.42", install_path:path);
  security_message(port:tomPort, data: report);
  exit(0);
}

exit(0);
