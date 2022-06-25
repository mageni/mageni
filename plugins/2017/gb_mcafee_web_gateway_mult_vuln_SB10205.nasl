###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_web_gateway_mult_vuln_SB10205.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# McAfee Web Gateway Multiple Vulnerabilities (SB10205)
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

CPE = "cpe:/a:mcafee:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811258");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2012-6706", "CVE-2017-1000364", "CVE-2017-1000366",
                "CVE-2017-1000368");
  script_bugtraq_id(98838, 99127, 99130);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-28 12:24:03 +0530 (Fri, 28 Jul 2017)");
  script_name("McAfee Web Gateway Multiple Vulnerabilities (SB10205)");

  script_tag(name:"summary", value:"This host is installed with McAfee Web
  Gateway and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An integer overflow error in 'DataSize+CurChannel' which results in a negative
    value of the 'DestPos' variable allowing to write out of bounds when setting
    Mem[DestPos].

  - An error in the size of the stack guard page on Linux, specifically a 4k stack
    guard page which is not sufficiently large and can be 'jumped' over (the stack
    guard page is bypassed).

  - An error in the glibc which allows specially crafted 'LD_LIBRARY_PATH' values
    to manipulate the heap/stack, causing them to alias.

  - An input validation (embedded newlines) error in the 'get_process_ttyname'
    function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute an arbitrary code and gain privileged access to affected
  system.");

  script_tag(name:"affected", value:"McAfee Web Gateway before 7.6.2.15 and
  7.7.x before 7.7.2.3");

  script_tag(name:"solution", value:"Upgrade to McAfee Web Gateway version
  7.6.2.15 or 7.7.2.3 or later.");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10205");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_mcafee_web_gateway_detect.nasl");
  script_mandatory_keys("McAfee/Web/Gateway/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.mcafee.com/us");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!mwgPort = get_app_port(cpe:CPE)){
  exit(0);
}

mwgVer = get_app_version(cpe:CPE, port:mwgPort);
if(!mwgVer){
  exit(0);
}

if(version_is_less(version:mwgVer, test_version:"7.6.2.15")){
  fix = "7.6.2.15";
}

if(mwgVer =~ "^7\.7" && version_is_less(version:mwgVer, test_version:"7.7.2.3")){
  fix = "7.7.2.3";
}

if(fix)
{
  report = report_fixed_ver( installed_version:mwgVer, fixed_version:fix);
  security_message( data:report, port:mwgPort);
  exit(0);
}
exit(0);
