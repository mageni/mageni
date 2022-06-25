##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_mis_crl_chk_win.nasl 13898 2019-02-27 08:37:43Z cfischer $
# OpenSSL Missing CRL sanity check Vulnerability (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107057");
  script_version("$Revision: 13898 $");
  script_cve_id("CVE-2016-7052");

  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"creation_date", value:"2016-09-26 06:40:16 +0200 (Mon, 26 Sep 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("OpenSSL Missing CRL sanity check Vulnerability (Windows)");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160926.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"OpenSSL suffers from the possibility of DoS attack after a bug fix added to OpenSSL
  1.1.0 but was omitted from OpenSSL 1.0.2i causing a null pointer exception when using CRLs in OpenSSL 1.0.2i.");

  script_tag(name:"impact", value:"Successful exploitation could result in a service crash.");

  script_tag(name:"affected", value:"OpenSSL 1.0.2i.");

  script_tag(name:"solution", value:"OpenSSL 1.0.2i users should upgrade to 1.0.2j.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_equal(version:vers, test_version:"1.0.2i"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.2j", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);