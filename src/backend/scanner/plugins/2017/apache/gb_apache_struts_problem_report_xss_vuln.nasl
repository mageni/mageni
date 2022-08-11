###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_problem_report_xss_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Apache Struts 'Problem Report' Cross-Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812011");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2015-5169");
  script_bugtraq_id(76625);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-06 17:52:42 +0530 (Fri, 06 Oct 2017)");
  ## Apache Struts contains a cross-site scripting vulnerability when devMode is left turned on
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Struts 'Problem Report' Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper validation
  of input passed via the 'Problem Report' screen when using debug mode.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary script code in the browser of user in the context of the
  affected site.");

  script_tag(name:"affected", value:"Apache Struts Versions 2.0.0 through 2.3.16.3");

  script_tag(name:"solution", value:"Upgrade to Apache Struts Version 2.3.20 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://struts.apache.org/docs/s2-025.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_detect.nasl");
  script_mandatory_keys("ApacheStruts/installed");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"http://struts.apache.org");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");


if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!appVer = get_app_version(cpe:CPE, port:appPort)){
  exit(0);
}

if(appVer =~ "^(2\.)")
{
  if(version_in_range(version:appVer, test_version:"2.0", test_version2:"2.3.16.3"))
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version:"2.3.20");
    security_message(data:report, port:appPort);
    exit(0);
  }
}
exit(0);
