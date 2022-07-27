###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_remote_code_exec_vuln_june.nasl 58255 2016-06-07 13:59:43 +0530 June$
#
# Apache Struts Remote Code Execution vulnerability June16
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
  script_oid("1.3.6.1.4.1.25623.1.0.808067");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-0785");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-07 13:59:43 +0530 (Tue, 07 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Struts Remote Code Execution vulnerability June16");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper validation
  of a non-spec URL-encoded parameter value including multi-byte characters.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Apache Struts Version 2.x through 2.3.24.1
  (except 2.3.20.3)");

  script_tag(name:"solution", value:"Upgrade to Apache Struts Version 2.3.20.3
  or 2.3.24.3 or 2.3.28 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://struts.apache.org/docs/s2-029.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_detect.nasl");
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
##version 2.3.20.3 is not vulnerable
if(version_is_equal(version:appVer, test_version:"2.3.20.3")){
  exit(0);
}

## Vulnerable version according to Advisory
else if(version_in_range(version:appVer, test_version:"2.0.0", test_version2:"2.3.24.1"))
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"2.3.20.3 or 2.3.24.3 or 2.3.28");
  security_message(data:report, port:appPort);
  exit(0);
}

