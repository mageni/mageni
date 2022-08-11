###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Struts2 Remote Code Execution Vulnerability (S2-057)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813786");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-11776");
  script_bugtraq_id(105125);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-23 12:45:43 +0530 (Thu, 23 Aug 2018)");
  script_name("Apache Struts2 Remote Code Execution Vulnerability (S2-057)");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_detect.nasl");
  script_mandatory_keys("ApacheStruts/installed");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-057");
  script_xref(name:"URL", value:"https://semmle.com/news/apache-struts-CVE-2018-11776");
  script_xref(name:"URL", value:"https://lgtm.com/blog/apache_struts_CVE-2018-11776");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to errors in conditions
  when namespace value isn't set for a result defined in underlying configurations
  and in same time, its upper action(s) configurations have no or wildcard
  namespace. Same possibility when using url tag which doesn't have value and
  action set and in same time, its upper action(s) configurations have no or
  wildcard namespace.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to possibly conduct remote code on the affected application.");

  script_tag(name:"affected", value:"Apache Struts versions 2.3 through 2.3.34,
  and 2.5 through 2.5.16");

  script_tag(name:"solution", value:"Upgrade to Apache Struts version 2.3.35 or
  2.5.17 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:appPort, exit_no_version:TRUE)) exit(0);
appVer = infos['version'];
path = infos['location'];

if(version_in_range(version:appVer, test_version:"2.3", test_version2:"2.3.34")){
  fix = "2.3.35";
}
else if(version_in_range(version:appVer, test_version:"2.5", test_version2:"2.5.16")){
  fix = "2.5.17";
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
  security_message(data:report, port:appPort);
  exit(0);
}

exit(0);