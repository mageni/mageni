###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomee_rce_vuln.nasl 71279 2017-06-28 16:34:52Z jun$
#
# Apache TomEE Remote Code Execution Vulnerability
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

CPE = "cpe:/a:apache:tomee";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810965");
  script_version("$Revision: 11962 $");
  script_cve_id("CVE-2016-0779");
  script_bugtraq_id(84422);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:51:32 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-28 17:04:45 +0530 (Wed, 28 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache TomEE Remote Code Execution Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Apache TomEE
  and is prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in
  EjbObjectInputStream class related to EJBd protocol.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code via a crafted serialized object.");

  script_tag(name:"affected", value:"Apache TomEE before 1.7.4 and 7.x
  before 7.0.0-M3.
  Note:This issue only affects you if you rely on EJBd protocol
  (proprietary remote EJB protocol). This one one is not activated by
  default on the 7.x series but it was on the 1.x ones.");

  script_tag(name:"solution", value:"Upgrade to version 1.7.4 or 7.0.0-M3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/537806/100/0/threaded");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q1/649");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomee_server_detect.nasl");
  script_mandatory_keys("Apache/TomEE/Server/ver");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"http://tomee.apache.org/");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if(!tomPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!appVer = get_app_version(cpe:CPE, port:tomPort)){
  exit(0);
}

if(version_is_less(version:appVer, test_version:"1.7.4")){
    fix = "1.7.4";
}

else if(appVer =~ "^7")
{
  if(revcomp(a: appVer, b: "7.0.0.M3") < 0){
    fix = "7.0.0-M3";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(data:report, port:tomPort);
  exit(0);
}
