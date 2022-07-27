###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_arbitrary_code_exec_vuln_june16.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Apache Struts Arbitrary Code Execution Vulnerability June16
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
  script_oid("1.3.6.1.4.1.25623.1.0.808080");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-3082");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-09 16:55:12 +0530 (Thu, 09 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Struts Arbitrary Code Execution Vulnerability June16");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to arbitrary code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as XSLTResult allows for the
  location of a stylesheet being passed as a request parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Apache Struts Version 2.0.0 through 2.3.28
  except 2.3.20.3 and 2.3.24.3");

  script_tag(name:"solution", value:"Upgrade to Apache Struts Version 2.3.20.3
  or 2.3.24.3 or 2.3.28.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://struts.apache.org/docs/s2-031.html");

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

else if(version_in_range(version:appVer, test_version:"2.0.0", test_version2:"2.3.28"))
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"2.3.20.3 or 2.3.24.3 or 2.3.28.1");
  security_message(data:report, port:appPort);
  exit(0);
}
