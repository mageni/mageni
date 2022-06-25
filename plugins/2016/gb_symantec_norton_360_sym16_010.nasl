###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_norton_360_sym16_010.nasl 11569 2018-09-24 10:29:54Z asteins $
#
# Symantec Norton 360 Decomposer Engine Multiple Parsing Vulnerabilities
#
# Authors:
# Tushar Khelge <tushar.khelge@secpod.com>
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

CPE = "cpe:/a:symantec:norton_360";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808516");
  script_version("$Revision: 11569 $");
  script_cve_id("CVE-2016-2207", "CVE-2016-2209", "CVE-2016-2210", "CVE-2016-2211",
                "CVE-2016-3644", "CVE-2016-3645", "CVE-2016-3646");
  script_bugtraq_id(91434, 91436, 91437, 91438, 91431, 91439, 91435);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-24 12:29:54 +0200 (Mon, 24 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-07-04 16:11:01 +0530 (Mon, 04 Jul 2016)");
  script_name("Symantec Norton 360 Decomposer Engine Multiple Parsing Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Norton 360 and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an error in
  Parsing of maliciously-formatted container files in Symantecs Decomposer engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause memory corruption, integer overflow or buffer overflow results in an
  application-level denial of service.");

  script_tag(name:"affected", value:"Symantec Norton 360 NGC 22.7 and prior.");

  script_tag(name:"solution", value:"Update Symantec Norton 360 through
  LiveUpdate.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_00");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_norton_360_detect.nasl");
  script_mandatory_keys("Symantec/Norton/360/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

##https://community.norton.com/en/comment/7056501#comment-7056501
if(version_is_less(version:sepVer, test_version:"22.7.0.76"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"22.7.0.76");
  security_message(data:report);
  exit(0);
}

