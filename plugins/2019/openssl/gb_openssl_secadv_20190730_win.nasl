# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142730");
  script_version("2019-08-14T09:16:05+0000");
  script_tag(name:"last_modification", value:"2019-08-14 09:16:05 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-14 06:03:58 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-1552");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Default Installation Paths Vulnerability (CVE-2019-1552) (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL on Windows is prone to an insecure path defaults vulnerability.");

  script_tag(name:"insight", value:"OpenSSL has internal defaults for a directory tree where it can find a
  configuration file as well as certificates used for verification in TLS. This directory is most commonly referred
  to as OPENSSLDIR, and is configurable with the --prefix / --openssldir configuration options.

  For OpenSSL versions 1.1.0 and 1.1.1, the mingw configuration targets assume that resulting programs and
  libraries are installed in a Unix-like environment and the default prefix for program installation as well as for
  OPENSSLDIR should be '/usr/local'.

  However, mingw programs are Windows programs, and as such, find themselves looking at sub-directories of
  'C:/usr/local', which may be world writable, which enables untrusted users to modify OpenSSL's default
  configuration, insert CA certificates, modify (or even replace) existing engine modules, etc.

  For OpenSSL 1.0.2, '/usr/local/ssl' is used as default for OPENSSLDIR on all Unix and Windows targets, including
  Visual C builds.  However, some build instructions for the diverse Windows targets on 1.0.2 encourage you to
  specify your own --prefix.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2 through 1.0.2s, 1.1.0 through 1.1.0k and 1.1.1 through 1.1.1c on Windows.");

  script_tag(name:"solution", value:"Apply the provided patches or update to a newer version.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20190730.txt");
  script_xref(name:"URL", value:"https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=54aa9d51b09d67e90db443f682cface795f5af9e");
  script_xref(name:"URL", value:"https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=b15a19c148384e73338aa7c5b12652138e35ed28");
  script_xref(name:"URL", value:"https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=d333ebaf9c77332754a9d5e111e2f53e1de54fdd");
  script_xref(name:"URL", value:"https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=e32bc855a81a2d48d215c506bdeb4f598045f7e9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
location = infos['location'];

if (version_in_range(version: version, test_version: "1.0.2", test_version2: "1.0.2s")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patch", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.1.0", test_version2: "1.1.0k")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patch", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.1.1", test_version2: "1.1.1c")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patch", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
