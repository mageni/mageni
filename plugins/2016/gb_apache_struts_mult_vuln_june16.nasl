###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_mult_vuln_june16.nasl 58255 2016-06-06 11:03:24 +0530 June$
#
# Apache Struts Multiple Vulnerabilities June16
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
  script_oid("1.3.6.1.4.1.25623.1.0.808021");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-4003", "CVE-2016-2162", "CVE-2016-3093");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-06 11:03:24 +0530 (Mon, 06 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Struts Multiple Vulnerabilities June16");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - The Apache Struts frameworks when forced, performs double evaluation of
    attributes' values assigned to certain tags so it is possible to pass in
    a value that will be evaluated again when a tag's attributes will be
    rendered.

  - The interceptor doesn't perform any validation of the user input and accept
    arbitrary string which can be used by a developer to display language
    selected by the user.

  - The application does not properly validate cache method references when used
    with OGNL before 3.0.12");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via multi-byte characters
  in a url-encoded parameter or a denial of service (block access to a web site)
  via unspecified vectors.");

  script_tag(name:"affected", value:"Apache Struts Version 2.x through 2.3.24.1");

  script_tag(name:"solution", value:"Upgrade to Apache Struts Version 2.3.28 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://struts.apache.org/docs/s2-030.html");
  script_xref(name:"URL", value:"http://struts.apache.org/docs/s2-028.html");
  script_xref(name:"URL", value:"https://struts.apache.org/docs/s2-034.html");

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

## Vulnerable version according to Advisory
if(version_in_range(version:appVer, test_version:"2.0.0", test_version2:"2.3.24.1"))
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"2.3.28");
  security_message(data:report, port:appPort);
  exit(0);
}
