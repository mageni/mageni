###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_universal_cmdb_info_disc_nd_code_exec_vuln.nasl 11837 2018-10-11 09:17:05Z asteins $
#
# HP Universal CMDB Remote Information Disclosure And Code Execution Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:hp:universal_cmbd_foundation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808251");
  script_version("$Revision: 11837 $");
  script_cve_id("CVE-2016-4367", "CVE-2016-4368");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 11:17:05 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-14 16:30:56 +0530 (Thu, 14 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("HP Universal CMDB Remote Information Disclosure And Code Execution Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with HP Universal
  CMDB and is prone to remote information disclosure and code execution
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified errors in Universal Discovery component and Apache Commons
  Collections (ACC) library in HPE Universal CMDB.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information via unspecified vectors and also
  to execute arbitrary commands.");

  script_tag(name:"affected", value:"HPE Universal CMDB versions
  10.0, 10.01, 10.10, 10.11, 10.20, and 10.21");

  script_tag(name:"solution", value:"Apply the available patch.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1036050");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137370");
  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05164813");
  script_xref(name:"URL", value:"https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05164408");
  script_xref(name:"URL", value:"https://softwaresupport.hpe.com/group/softwaresupport/search-result/-/facetsearch/document/KM02310095");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hpe_universal_cmdb_detect.nasl");
  script_mandatory_keys("HP/UCMDB/Installed");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"https://softwaresupport.hpe.com/group/softwaresupport/search-result/-/facetsearch/document/KM02241206");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!ucmdbPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ucmdbVer = get_app_version(cpe:CPE, port:ucmdbPort)){
  exit(0);
}

if(version_is_equal(version:ucmdbVer, test_version:"10.0") ||
   version_is_equal(version:ucmdbVer, test_version:"10.01") ||
   version_is_equal(version:ucmdbVer, test_version:"10.10") ||
   version_is_equal(version:ucmdbVer, test_version:"10.11") ||
   version_is_equal(version:ucmdbVer, test_version:"10.20") ||
   version_is_equal(version:ucmdbVer, test_version:"10.21"))
{
  report = report_fixed_ver(installed_version: ucmdbVer, fixed_version: "Apply the patch");
  security_message(data:report, port:ucmdbPort);
  exit(0);
}
