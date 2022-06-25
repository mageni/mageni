###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nitro_pro_dos_n_code_exec_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Nitro Pro Denial-of-Service and Code Execution Vulnerabilities (Windows)
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

CPE = "cpe:/a:nitro_software:nitro_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811273");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-7950", "CVE-2017-2796");
  script_bugtraq_id(99514);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 16:25:44 +0530 (Fri, 04 Aug 2017)");
  script_name("Nitro Pro Denial-of-Service and Code Execution Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with Nitro Pro
  and is prone to denial-of-service and code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to improper handling
  of a crafted PCX file and an out of bound write error in the PDF parsing
  functionality");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a denial-of-service (application crash) condition and
  execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Nitro Pro version 11.0.3 (11.0.3.134)
  and prior.");

  script_tag(name:"solution", value:"Upgrade to Nitro Pro version 11.0.3.173
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.gonitro.com/product/downloads#securityUpdates");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0289");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_nitro_pro_detect_win.nasl");
  script_mandatory_keys("Nitro/Pro/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!nitroVer = get_app_version(cpe:CPE, nofork:TRUE)){
  exit(0);
}

if(version_is_less(version:nitroVer, test_version:"11.0.3.173"))
{
  report = report_fixed_ver(installed_version:nitroVer, fixed_version:"11.0.3.173");
  security_message(data:report);
  exit(0);
}
