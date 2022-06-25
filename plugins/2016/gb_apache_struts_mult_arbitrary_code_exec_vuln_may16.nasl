###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_mult_arbitrary_code_exec_vuln_may16.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Apache Struts Multiple Arbitrary Code Execution Vulnerabilities May16
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807972");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-3081", "CVE-2016-3087");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-06 15:32:08 +0530 (Fri, 06 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Struts Multiple Arbitrary Code Execution Vulnerabilities May16");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to multiple arbitrary code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - An error occurs in prefix method when Dynamic Method Invocation is enabled.

  - An error occurs in REST Plugin with ! when Dynamic Method Invocation is
    enabled.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Apache Struts Version 2.3.20 through 2.3.28
  except 2.3.20.3 and 2.3.24.3");

  script_tag(name:"solution", value:"Upgrade to Apache Struts Version 2.3.20.3
  or 2.3.24.3 or 2.3.28.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://struts.apache.org/docs/s2-033.html");
  script_xref(name:"URL", value:"http://struts.apache.org/docs/s2-032.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheStruts/installed");
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

## Vulnerable version according to Advisory
if(version_is_equal(version:appVer, test_version:"2.3.20.3")||
   version_is_equal(version:appVer, test_version:"2.3.24.3")){
  exit(0);
}

else if(version_in_range(version:appVer, test_version:"2.3.20", test_version2:"2.3.28"))
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"2.3.28.1 or 2.3.20.3 or 2.3.24.3");
  security_message(data:report, port:appPort);
  exit(0);
}
