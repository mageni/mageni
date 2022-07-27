###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_loadrunner_stack_bof_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# HPE LoadRunner 'magentproc.exe' Stack Buffer Overflow Vulnerability
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

CPE = "cpe:/a:hp:loadrunner";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810529");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2013-4800");
  script_bugtraq_id(61446);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-03 13:26:14 +0530 (Fri, 03 Feb 2017)");
  script_name("HPE LoadRunner 'magentproc.exe' Stack Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"This host is installed with HPE LoadRunner
  and is prone to stack buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation of a length value in SSL communication with the 'magentproc.exe'.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to execute arbitrary code and unsuccessful
  attempts can cause a denial-of-service condition.");

  script_tag(name:"affected", value:"HPE LoadRunner versions prior to 11.52");

  script_tag(name:"solution", value:"Upgrade to HPE LoadRunner version 11.52
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-169");
  script_xref(name:"URL", value:"http://telussecuritylabs.com/threats/show/TSL20130725-15");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_hpe_loadrunner_detect.nasl");
  script_mandatory_keys("HPE/LoadRunner/Win/Ver");
  script_xref(name:"URL", value:"https://www.hpe.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:hpVer, test_version:"11.52"))
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"11.52");
  security_message(data:report);
  exit(0);
}
