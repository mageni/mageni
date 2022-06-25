###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_dos_vuln_nov16_win.nasl 11938 2018-10-17 10:08:39Z asteins $
#
# Apache Struts Denial of Service Vulnerability Nov16 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808537");
  script_version("$Revision: 11938 $");
  script_cve_id("CVE-2016-4465");
  script_bugtraq_id(91278);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-18 14:36:30 +0530 (Fri, 18 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Struts Denial of Service Vulnerability Nov16 (Windows)");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an issue in
  URLValidator.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service.");

  script_tag(name:"affected", value:"Apache Struts Version 2.3.20 through 2.3.28.1
  and 2.5 on Windows");

  script_tag(name:"solution", value:"Upgrade to Apache Struts Version 2.3.29
  or 2.5.1 later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://struts.apache.org/docs/s2-041.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_apache_struts_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheStruts/installed", "Host/runs_windows");
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

## Vulnerable version according to Advisory

if(appVer =~ "^(2\.)")
{
  if(version_is_equal(version:appVer, test_version:"2.5"))
  {
    fix = "2.5.1";
    VULN = TRUE ;
  }

  else if(version_in_range(version:appVer, test_version:"2.3.20", test_version2:"2.3.28.1"))
  {
    fix = "2.3.29";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(data:report, port:appPort);
  exit(0);
}
