###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_indusoft_web_studio_priv_escal_vuln_aug17.nasl 14057 2019-03-08 13:02:00Z jschulte $
#
# InduSoft Web Studio Privilege Escalation Vulnerability Aug17 (Windows)
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

CPE = "cpe:/a:schneider_electric:indusoft_web_studio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811264");
  script_version("$Revision: 14057 $");
  script_cve_id("CVE-2017-7968");
  script_bugtraq_id(98544);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:02:00 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-08-01 17:07:48 +0530 (Tue, 01 Aug 2017)");
  script_name("InduSoft Web Studio Privilege Escalation Vulnerability Aug17 (Windows)");

  script_tag(name:"summary", value:"This host is installed with InduSoft Web
  Studio and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an incorrect default
  permissions for a new directory and two files, created on installation.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  authenticated user to escalate his or her privileges and manipulate certain
  files.");

  script_tag(name:"affected", value:"Schneider Electric InduSoft Web Studio
  before 8.0 Service Pack 1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Schneider Electric InduSoft
  Web Studio 8.0 Service Pack 1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-138-02");
  script_xref(name:"URL", value:"http://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2017-090-02");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(version_is_less(version:studioVer, test_version:"8.0.1.0"))
{
  report = report_fixed_ver( installed_version:studioVer, fixed_version:"8.0.1.0");
  security_message( data:report);
  exit(0);
}
