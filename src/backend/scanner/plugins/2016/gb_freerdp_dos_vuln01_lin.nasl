###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freerdp_dos_vuln01_lin.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# FreeRDP Denial of Service Vulnerability-01 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:freerdp_project:freerdp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809738");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2013-4118");
  script_bugtraq_id(61072);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-01 17:37:04 +0530 (Thu, 01 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_name("FreeRDP Denial of Service Vulnerability-01 (Linux)");
  script_tag(name:"summary", value:"The host is installed with FreeRDP and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the NULL pointer
  dereference error within the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attackers to cause a denial of service condition.");

  script_tag(name:"affected", value:"FreeRDP before 1.1.0-beta1 on Linux");

  script_tag(name:"solution", value:"Upgrade to FreeRDP version 1.1.0-beta1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/07/12/2");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/07/11/12");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");
  script_xref(name:"URL", value:"http://www.freerdp.com");
  exit(0);
}


include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(!installVer = get_app_version(cpe:CPE)){
  exit(0);
}

##Using revcomp to compare package version precisely
if(revcomp(a:installVer, b: "1.1.0-beta1") < 0)
{
  report = report_fixed_ver(installed_version: installVer, fixed_version: "1.1.0-beta1");
  security_message(data: report);
  exit(0);
}
exit(0);
