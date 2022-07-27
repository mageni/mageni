##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icecast_buf_ovflw_vuln.nasl 13316 2019-01-28 07:41:51Z asteins $
#
# Icecast < 2.4.4 Buffer Overflow Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = 'cpe:/a:icecast:icecast';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141647");
  script_version("$Revision: 13316 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-28 08:41:51 +0100 (Mon, 28 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-11-06 08:48:35 +0700 (Tue, 06 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-18820");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Icecast < 2.4.4 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_icecast_detect.nasl");
  script_mandatory_keys("icecast/detected");

  script_tag(name:"summary", value:"A buffer overflow was discovered in the URL-authentication backend of the
Icecast. If the backend is enabled, then any malicious HTTP client can send a request for that specific resource
including a crafted header, leading to denial of service and potentially remote code execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Icecast versions prior to 2.4.4.");

  script_tag(name:"solution", value:"Update to version 2.4.4 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/11/01/3");
  script_xref(name:"URL", value:"https://gitlab.xiph.org/xiph/icecast-server/issues/2342");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
