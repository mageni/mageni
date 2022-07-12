###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tsm_client_acceptor_daemon_dos_vuln_lin.nasl 11835 2018-10-11 08:38:49Z mmartin $
#
# IBM TSM Client 'Client Acceptor Daemon' Denial-of-Service Vulnerability - Linux
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

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:tivoli_storage_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811076");
  script_version("$Revision: 11835 $");
  script_cve_id("CVE-2015-4951");
  script_bugtraq_id(81436);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 10:38:49 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-05 10:20:10 +0530 (Mon, 05 Jun 2017)");
  script_name("IBM TSM Client 'Client Acceptor Daemon' Denial-of-Service Vulnerability - Linux");

  script_tag(name:"summary", value:"This host is installed with IBM Tivoli Storage
  Manager Client and is prone to denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in client
  acceptor daemon in the client within IBM Tivoli Storage Manager which is not
  able to handle a crafted Web client URL.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service (daemon crash) condition.");

  script_tag(name:"affected", value:"Tivoli Storage Manager Client versions
  7.1.0.0 through 7.1.2.x, 6.4.0.0 through 6.4.3.0, 6.3.0.0 through 6.3.2.4,
  6.2, 6.1, and 5.5 all levels.");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Storage Manager Client
  version 7.1.3 or 6.4.3.1 or 6.3.2.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21973484");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_ibm_tiv_tsm_detect_lin.nasl");
  script_mandatory_keys("IBM/Tivoli/Storage/Manager/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!tivVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:tivVer, test_version:"5.5", test_version2:"6.3.2.4")){
  fix = "6.3.2.5";
}

else if(version_in_range(version:tivVer, test_version:"6.4", test_version2:"6.4.3.0")){
  fix = "6.4.3.1";
}

else if((tivVer=~ "^7\.1\.") && version_is_less(version:tivVer, test_version:"7.1.3")){
  fix = "7.1.3";
}

if(fix)
{
  report = report_fixed_ver(installed_version:tivVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
