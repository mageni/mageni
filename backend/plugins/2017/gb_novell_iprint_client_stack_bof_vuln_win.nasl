###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_iprint_client_stack_bof_vuln_win.nasl 11935 2018-10-17 08:47:01Z mmartin $
#
# Novell iPrint Client Stack Buffer Overflow Vulnerability (Windows)
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

CPE = "cpe:/a:novell:iprint";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810590");
  script_version("$Revision: 11935 $");
  script_cve_id("CVE-2013-1091");
  script_bugtraq_id(59612);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 10:47:01 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-14 13:19:08 +0530 (Tue, 14 Mar 2017)");
  script_name("Novell iPrint Client Stack Buffer Overflow Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Novell iPrint Client
  and is prone to stack-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the application fails
  to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the application.
  Failed exploit attempts likely result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Novell iPrint Client versions before 5.90 on Windows");

  script_tag(name:"solution", value:"Upgrade to Novell iPrint Client 5.90 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7012344");
  script_xref(name:"URL", value:"https://www.symantec.com/security_response/attacksignatures/detail.jsp?asid=27335");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/iPrint/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!niVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:niVer, test_version:"5.90"))
{
  report = report_fixed_ver(installed_version:niVer, fixed_version:"5.90");
  security_message(data:report);
  exit(0);
}
