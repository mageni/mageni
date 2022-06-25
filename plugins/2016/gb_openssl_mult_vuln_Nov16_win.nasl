##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_mult_vuln_Nov16_win.nasl 13898 2019-02-27 08:37:43Z cfischer $
# OpenSSL Multiple Vulnerabilities - Nov 16 (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107080");
  script_version("$Revision: 13898 $");
  script_cve_id("CVE-2016-7054", "CVE-2016-7053");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-11-11 11:19:11 +0100 (Fri, 11 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenSSL Multiple Vulnerabilities - Nov 16 (Windows)");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  1. TLS connections using *-CHACHA20-POLY1305 ciphersuites are susceptible to a DoS attack by corrupting larger payloads. This can result in an OpenSSL crash.

  2. Applications parsing invalid CMS structures can crash with a NULL pointer dereference.
  This is caused  by a bug in the handling of the ASN.1 CHOICE type in OpenSSL 1.1.0 which can result in a NULL value being
  passed to the structure callback if an attempt is made to free certain invalid encodings. Only CHOICE structures
  using a callback which do not handle NULL value are affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of service.");

  script_tag(name:"affected", value:"OpenSSL 1.1.0 versions prior to 1.1.0c");

  script_tag(name:"solution", value:"OpenSSL 1.1.0 users should upgrade to 1.1.0c.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20161110.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

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

if(vers =~ "^(1\.1\.0)" && version_is_less(version:vers, test_version:"1.1.0c"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.1.0c", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);