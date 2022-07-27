###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_indusoft_web_studio_info_disc_vuln_win.nasl 14057 2019-03-08 13:02:00Z jschulte $
#
# InduSoft Web Studio Information Disclosure Vulnerability August15 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806002");
  script_version("$Revision: 14057 $");
  script_cve_id("CVE-2015-1009");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:02:00 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-08-19 15:48:22 +0530 (Wed, 19 Aug 2015)");
  script_name("InduSoft Web Studio Information Disclosure Vulnerability August15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with InduSoft Web
  Studio and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to usage of cleartext for
  project-window password storage.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  local users to obtain sensitive information by reading a file.");

  script_tag(name:"affected", value:"Schneider Electric InduSoft Web Studio
  before 7.1.3.5 Patch 5 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Schneider Electric InduSoft
  Web Studio 7.1.3.5 Patch 5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.scip.ch/en/?vuldb.76853");
  script_xref(name:"URL", value:"http://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2015-100-01");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_schneider_indusoft_consolidation.nasl");
  script_mandatory_keys("schneider_indusoft/installed");
  script_xref(name:"URL", value:"http://www.indusoft.com/");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!studioVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Version 7.1.3.5 == v 7.1 SP3 Patch 5
if(version_is_less(version:studioVer, test_version:"7.1.3.5"))
{
   report = report_fixed_ver(installed_version:studioVer, fixed_version:"7.1.3.5");
   security_message(data:report);
   exit(0);
}
