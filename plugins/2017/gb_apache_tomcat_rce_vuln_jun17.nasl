###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_rce_vuln_jun17.nasl 71279 2017-06-28 16:34:52Z jun$
#
# Apache Tomcat 'JmxRemoteLifecycleListener' Remote Code Execution Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810966");
  script_version("2019-05-10T11:41:35+0000");
  script_cve_id("CVE-2016-8735");
  script_bugtraq_id(94463);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-06-28 17:04:45 +0530 (Wed, 28 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Tomcat 'JmxRemoteLifecycleListener' Remote Code Execution Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in
  'JmxRemoteLifecycleListener'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Apache Tomcat before 6.0.48, 7.x before
  7.0.73, 8.x before 8.0.39, 8.5.x before 8.5.7, and 9.x before 9.0.0.M12.
  Note:This issue exists if JmxRemoteLifecycleListener is used and an attacker
  can reach JMX ports.");

  script_tag(name:"solution", value:"Upgrade to version 6.0.48, or 7.0.73 or
  8.0.39 or 8.5.8 or 9.0.0.M13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/502");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if(isnull(tomPort = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:tomPort, exit_no_version:TRUE))
  exit(0);

appVer = infos["version"];
path = infos["location"];

if(version_is_less(version:appVer, test_version:"6.0.48")){
    fix = "6.0.48";
}
else if(appVer =~ "^7\.")
{
  if(revcomp(a: appVer, b: "7.0.73") < 0){
    fix = "7.0.73";
  }
}
else if(appVer =~ "^8\.5\.")
{
  if(revcomp(a: appVer, b: "8.5.8") < 0){
    fix = "8.5.8";
  }
}
else if(appVer =~ "^8\.")
{
  if(revcomp(a: appVer, b: "8.0.39") < 0){
    fix = "8.0.39";
  }
}
else if(appVer =~ "^9\.")
{
  if(revcomp(a: appVer, b: "9.0.0.M13") < 0){
    fix = "9.0.0-M13";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
  security_message(data:report, port:tomPort);
  exit(0);
}
