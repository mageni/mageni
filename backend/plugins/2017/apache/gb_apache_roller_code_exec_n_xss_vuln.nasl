###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Roller Cross Site Scripting And Code Execution Vulnerabilities
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

CPE = "cpe:/a:apache:roller";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812226");
  script_version("2019-05-17T13:14:58+0000");
  script_cve_id("CVE-2013-4171", "CVE-2013-4212");
  script_bugtraq_id(63963, 63928);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 13:14:58 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-11-27 14:43:15 +0530 (Mon, 27 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Roller Cross Site Scripting And Code Execution Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Apache Roller
  and is prone to code execution and cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An input validation errors via some parameters in certain 'getText' methods
    in the 'ActionSupport' controller in Apache Roller.

  - Multiple input validation errors of vectors related to the search results in
    the 'RSS' and 'Atom' feed templates.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to inject arbitrary web script or HTML and also to execute arbitrary
  commands.");

  script_tag(name:"affected", value:"Apache Roller before 5.0.2");

  script_tag(name:"solution", value:"Upgrade to Apache Roller 5.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/29859");
  script_xref(name:"URL", value:"http://rollerweblogger.org/project/entry/apache_roller_5_0_2");
  script_xref(name:"URL", value:"http://security.coverity.com/advisory/2013/Oct/remote-code-execution-in-apache-roller-via-ognl-injection.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_roller_detect.nasl");
  script_mandatory_keys("ApacheRoller/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE)) exit(0);
rollerVer = infos['version'];
rollerpath = infos['location'];

if(version_is_less(version:rollerVer, test_version:"5.0.2"))
{
  report = report_fixed_ver(installed_version:rollerVer, fixed_version:"5.0.2", install_path:rollerpath);
  security_message(data:report);
  exit(0);
}
exit(0);
