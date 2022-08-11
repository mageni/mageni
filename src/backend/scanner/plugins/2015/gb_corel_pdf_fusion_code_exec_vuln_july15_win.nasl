###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_corel_pdf_fusion_code_exec_vuln_july15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Corel PDF Fusion Arbitrary Code Execution Vulnerability July15 (Windows)
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

CPE = "cpe:/a:corel:pdf_fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805674");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-8396");
  script_bugtraq_id(72007);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-07 16:52:25 +0530 (Tue, 07 Jul 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Corel PDF Fusion Arbitrary Code Execution Vulnerability July15 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Corel PDF
  Fusion and is prone to arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the way it loads
  dynamic-link libraries (DLL) such as the 'wintab32.dll' or 'quserex.dll'
  libraries. The program uses a fixed path to look for specific files or
  libraries. This path includes directories that may not be trusted or under
  user control.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to inject custom code.");

  script_tag(name:"affected", value:"Corel PDF Fusion prior or equal to 1.14
  on Windows.");

  script_tag(name:"solution", value:"As a workaround users should avoid opening
  untrusted files whose extensions are associated with Corel software and contain
  any of the DLL files.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"http://www.coresecurity.com/advisories/corel-software-dll-hijacking");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_corel_pdf_fusion_detect_win.nasl");
  script_mandatory_keys("Corel/PDF/Fusion/Win/Ver");
  script_xref(name:"URL", value:"http://www.corel.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!corelVer = get_app_version(cpe:CPE))
{
  exit(0);
}

if(version_is_less_equal(version:corelVer, test_version:"1.14"))
{
  report = 'Installed version: ' + corelVer + '\n' +
             'Fixed version:     ' + "Workaround" + '\n';
  security_message(data:report );
  exit(0);
}
