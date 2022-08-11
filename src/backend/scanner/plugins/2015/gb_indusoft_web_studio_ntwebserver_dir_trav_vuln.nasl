###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_indusoft_web_studio_ntwebserver_dir_trav_vuln.nasl 14057 2019-03-08 13:02:00Z jschulte $
#
# InduSoft Web Studio 'NTWebServer' Directory Traversal Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806642");
  script_version("$Revision: 14057 $");
  script_cve_id("CVE-2014-0780");
  script_bugtraq_id(67056);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:02:00 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-12-07 13:44:29 +0530 (Mon, 07 Dec 2015)");
  script_name("InduSoft Web Studio 'NTWebServer' Directory Traversal Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with InduSoft Web
  Studio and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  'NTWebServer' (test web server installed with InduSoft Web Studio).");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to read files outside the web root and possibly perform arbitrary
  code execution.");

  script_tag(name:"affected", value:"InduSoft Web Studio version 7.1
  before SP2 Patch 4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to InduSoft Web Studio version
  7.1 SP2 Patch 4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-14-107-02");

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

## Version 7.1 SP2 Patch 4 == 7.1.2.4

if (studioVer =~ "^(7.1\.)")
{
  if(version_is_less(version:studioVer, test_version:"7.1.2.4"))
  {
     report = report_fixed_ver(installed_version:studioVer, fixed_version:"7.1.2.4");
     security_message(data:report);
     exit(0);
  }
}
