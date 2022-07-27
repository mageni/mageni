###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teamviewer_ses_hijack_vuln.nasl 11835 2018-10-11 08:38:49Z mmartin $
#
# Teamviewer Session Hijacking Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:teamviewer:teamviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107273");
  script_version("$Revision: 11835 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"last_modification", value:"$Date: 2018-10-11 10:38:49 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-11 09:50:38 +0700 (Mon, 11 Dec 2017)");
  script_name("Teamviewer Session Hijacking Vulnerability");

  script_tag(name:"summary", value:"Teamviewer is vulnerable to session hijacking.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused through an injectable C++ DLL which takes advantage of the bug to change TeamViewer permissions");

  script_tag(name:"impact", value:"Successful exploitation can give local users power over another system involved in a session and seize control of PCs through desktop sessions.");

  script_tag(name:"affected", value:"Teamviewer before 13.0.5640.0");

  script_tag(name:"solution", value:"Update to Teamviewer 13.0.5640.0");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.zdnet.com/article/teamviewer-issues-emergency-fix-for-remote-access-vulnerability/");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:Ver, test_version:"13.0.5640.0"))
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:"13.0.5640.0");
  security_message(data:report);
  exit(0);
}
