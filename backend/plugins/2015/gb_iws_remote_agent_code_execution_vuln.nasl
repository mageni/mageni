###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iws_remote_agent_code_execution_vuln.nasl 14057 2019-03-08 13:02:00Z jschulte $
#
# InduSoft Web Studio 'Remote Agent' Code Execution Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806643");
  script_version("$Revision: 14057 $");
  script_cve_id("CVE-2015-7374");
  script_bugtraq_id(76864);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:02:00 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-12-07 14:48:04 +0530 (Mon, 07 Dec 2015)");
  script_name("InduSoft Web Studio 'Remote Agent' Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with InduSoft Web
  Studio and is prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  error in remote agent component within the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"InduSoft Web Studio 7.1.3.6 and
  all previous versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to InduSoft Web Studio version
  8.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2015-251-01");

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

if(version_is_less_equal(version:studioVer, test_version:"7.1.3.6"))
{
  report = report_fixed_ver(installed_version:studioVer, fixed_version:"8.0");
  security_message(data:report);
  exit(0);
}
