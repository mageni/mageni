###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_request_tracker_mult_vuln.nasl 11901 2018-10-15 08:47:18Z mmartin $
#
# Request Tracker Multiple Vulnerabilities
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

CPE = "cpe:/a:best_practical_solutions:request_tracker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811527");
  script_version("$Revision: 11901 $");
  script_cve_id("CVE-2017-5944", "CVE-2016-6127", "CVE-2017-5943");
  script_bugtraq_id(99381, 99384, 99375);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 10:47:18 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-18 16:33:24 +0530 (Tue, 18 Jul 2017)");
  script_name("Request Tracker Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Request Tracker
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Not using a constant-time comparison algorithm for secrets.

  - It fails to properly validate HTTP requests.

  - Multiple input validation errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application.
  Failed exploits will result in denial-of-service conditions, perform certain
  unauthorized actions and gain access to the affected application and obtain
  sensitive user password information. Other attacks are also possible.");

  script_tag(name:"affected", value:"Request Tracker 4.x before 4.0.25, 4.2.x
  before 4.2.14, and 4.4.x before 4.4.2");

  script_tag(name:"solution", value:"Upgrade to Request Tracker version 4.0.25 or
  4.2.14 or 4.4.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://forum.bestpractical.com/t/security-vulnerabilities-in-rt-2017-06-15/32016");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("rt_detect.nasl");
  script_mandatory_keys("RequestTracker/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!rtPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!rtVer = get_app_version(cpe:CPE, port:rtPort)){
  exit(0);
}

if(rtVer =~ "(^4\.)")
{
  if(version_is_less(version:rtVer, test_version:"4.0.25")){
    fix = "4.0.25";
  }

  else if(rtVer =~ "(^4\.2)" && version_is_less(version:rtVer, test_version:"4.2.14")){
    fix = "4.2.14";
  }

  else if(rtVer =~ "(^4\.4)" && version_is_less(version:rtVer, test_version:"4.4.2")){
    fix = "4.4.2";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:rtVer, fixed_version:fix);
  security_message(port:rtPort, data:report);
  exit(0);
}
exit(0);
