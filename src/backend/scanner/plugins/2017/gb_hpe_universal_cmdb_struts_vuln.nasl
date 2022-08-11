###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_universal_cmdb_struts_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# HPE Universal CMDB Remote Code Execution Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:hp:universal_cmbd_foundation';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106736");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-10 12:58:34 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-5638");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HPE Universal CMDB Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hpe_universal_cmdb_detect.nasl");
  script_mandatory_keys("HP/UCMDB/Installed");

  script_tag(name:"summary", value:"HPE Universal CMDB is prone to a remote code execution vulnerability in
Apache Struts.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A potential security vulnerability in Jakarta Multipart parser in Apache
Struts has been addressed in HPE Universal CMDB. This vulnerability could be remotely exploited to allow code
execution via mishandled file upload.");

  script_tag(name:"affected", value:"HP Universal CMDB Foundation Software v10.22 CUP5");

  script_tag(name:"solution", value:"HPE has made mitigation information available to resolve the vulnerability
for the impacted versions of HPE Universal CMDB.");

  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03733en_us");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "10.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
