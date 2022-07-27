###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_urlvalidator_dos_vuln_lin_oct17.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Apache Struts 'URLValidator' Denial-Of-Service Vulnerability - Oct17 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.812000");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2016-8738");
  script_bugtraq_id(94657);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-28 13:02:47 +0530 (Thu, 28 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Struts 'URLValidator' Denial-Of-Service Vulnerability - Oct17 (Linux)");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient validation
  of input in a form field by the built-in URLValidator.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  prepare a special URL which will be used to overload server process when
  performing validation of the URL and conduct a denial-of-service condition.");

  script_tag(name:"affected", value:"Apache Struts Version 2.5 through 2.5.5
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Apache Struts Version 2.5.8 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://struts.apache.org/docs/s2-044.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_apache_struts_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ApacheStruts/installed", "Host/runs_unixoide");
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

if(appVer =~ "^(2\.5)")
{
  if(version_in_range(version:appVer, test_version:"2.5", test_version2:"2.5.5"))
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version:"2.5.8");
    security_message(data:report, port:appPort);
    exit(0);
  }
}
exit(0);
