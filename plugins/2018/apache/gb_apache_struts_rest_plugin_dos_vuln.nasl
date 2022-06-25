###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Struts 'REST' Plugin DoS Vulnerability
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813062");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-1327");
  script_bugtraq_id(103516);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-02 16:08:37 +0530 (Mon, 02 Apr 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  ## It may lead to FP because older versions can implement custom XML handler based
  ## on the Jackson XML handler from the Apache Struts 2.5.16
  script_name("Apache Struts 'REST' Plugin DoS Vulnerability");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to REST Plugin which is using
  XStream library which is vulnerable and allow to perform a DoS attack when using
  a malicious request with specially crafted XML payload.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  perform a DoS attack when using a malicious request with specially crafted XML
  payload.");

  script_tag(name:"affected", value:"Apache Struts Version 2.1.1 through 2.5.14.1");

  script_tag(name:"solution", value:"Upgrade to Apache Struts Version 2.5.16 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-056");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
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

if(!infos = get_app_version_and_location(cpe:CPE, port:appPort, exit_no_version:TRUE)) exit(0);
appVer = infos['version'];
path = infos['location'];

if(version_in_range(version:appVer, test_version:"2.1.1", test_version2:"2.5.14.1"))
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"2.5.16", install_path:path);
  security_message(data:report, port:appPort);
  exit(0);
}
exit(0);
