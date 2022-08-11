###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_endpoint_encryption_info_disc_vuln.nasl 11903 2018-10-15 10:26:16Z asteins $
#
# Symantec Endpoint Encryption Client Memory Dump Information Disclosure Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE= "cpe:/a:symantec:endpoint_encryption";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808071");
  script_version("$Revision: 11903 $");
  script_cve_id("CVE-2015-6556");
  script_tag(name:"cvss_base", value:"2.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 12:26:16 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-07 13:17:49 +0530 (Tue, 07 Jun 2016)");
  script_name("Symantec Endpoint Encryption Client Memory Dump Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Endpoint Encryption (SEE) and is prone to information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an access to a memory
  dump of 'EACommunicatorSrv.exe' in the Framework Service.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to discover credentials by triggering a memory dump.");

  script_tag(name:"affected", value:"Symantec Endpoint Encryption (SEE) version
  prior to 11.1.0.");

  script_tag(name:"solution", value:"Update to Symantec Endpoint Encryption (SEE)
  version 11.1.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20151214_00");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_endpoint_encryption_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Encryption/Win/Ver");
  script_xref(name:"URL", value:"http://www.symantec.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!seeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:seeVer, test_version:"11.1.0"))
{
  report = report_fixed_ver(installed_version:seeVer, fixed_version: "11.1.0");
  security_message(data:report);
  exit(0);
}
