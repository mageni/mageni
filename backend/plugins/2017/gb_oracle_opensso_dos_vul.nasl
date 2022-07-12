###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_opensso_dos_vul.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Oracle OpenSSO 'Web Agents' Denial of Service Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:oracle:opensso";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811405");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2016-2834");
  script_bugtraq_id(91072);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-01 15:25:23 +0530 (Tue, 01 Aug 2017)");
  script_name("Oracle OpenSSO 'Web Agents' Denial of Service Vulnerability");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_sun_opensso_detect.nasl");
  script_mandatory_keys("Oracle/OpenSSO/detected");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");

  script_tag(name:"summary", value:"This host is installed with oracle OpenSSO
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in Network
  Security Services (NSS) before 3.23.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (memory corruption and application
  crash) or possibly have unspecified other impact via unknown vectors.");

  script_tag(name:"affected", value:"Oracle OpenSSO 3.0.0.8.");

  script_tag(name:"solution", value:"Updates are available, Apply Updates from the
  reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: The version check below is completely broken and doesn't match the version 8.0 of "real" services exposed...

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(! openssoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(! vers = get_app_version(cpe:CPE, port:openssoPort)){
  exit(0);
}

if(version_is_equal(version:vers, test_version:"3.0.0.8")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references");
  security_message(port:openssoPort, data:report);
  exit(0);
}

exit(99);
