###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_indusoft_web_studio_stack_bof_vuln_nov17.nasl 14057 2019-03-08 13:02:00Z jschulte $
#
# InduSoft Web Studio Unspecified Stack Buffer Overflow Vulnerability (Windows)
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

CPE = "cpe:/a:schneider_electric:indusoft_web_studio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812215");
  script_version("$Revision: 14057 $");
  script_cve_id("CVE-2017-14024");
  script_bugtraq_id(101779);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:02:00 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-11-17 16:09:59 +0530 (Fri, 17 Nov 2017)");
  script_name("InduSoft Web Studio Unspecified Stack Buffer Overflow Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_schneider_indusoft_consolidation.nasl");
  script_mandatory_keys("schneider_indusoft/installed");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-313-02");
  script_xref(name:"URL", value:"http://www.indusoft.com");

  script_tag(name:"summary", value:"This host is installed with InduSoft Web
  Studio and is prone to an unspecified stack buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified
  stack-based buffer overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  a remote attacker to remotely execute code with high privileges.");

  script_tag(name:"affected", value:"Schneider Electric InduSoft Web Studio
  8.0 SP2 Patch 1 and prior versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to InduSoft Web Studio
  version 8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE)) exit(0);
studioVer = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:studioVer, test_version:"8.0.2.1"))
{
  report = report_fixed_ver( installed_version:studioVer, fixed_version:"IWS 8.1", install_path:path );
  security_message( data:report);
  exit(0);
}
