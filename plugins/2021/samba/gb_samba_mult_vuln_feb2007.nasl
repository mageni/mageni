# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150723");
  script_version("2021-09-29T04:35:02+0000");
  script_tag(name:"last_modification", value:"2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-09-24 10:59:30 +0000 (Fri, 24 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2007-0452", "CVE-2007-0454");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba 3.0.6 <= 3.0.23d Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2007-0452:

  Internally Samba's file server daemon, smbd, implements
  support for deferred file open calls in an attempt to serve
  client requests that would otherwise fail due to a share mode
  violation.  When renaming a file under certain circumstances
  it is possible that the request is never removed from the deferred
  open queue.  smbd will then become stuck is a loop trying to
  service the open request.

  This bug may allow an authenticated user to exhaust resources
  such as memory and CPU on the server by opening multiple CIFS
  sessions, each of which will normally spawn a new smbd process,
  and sending each connection into an infinite loop.

  - CVE-2007-0454:

  NOTE: This security advisory only impacts Samba servers
  that share AFS file systems to CIFS clients and which have
  been explicitly instructed in smb.conf to load the afsacl.so
  VFS module.

  The source defect results in the name of a file stored on
  disk being used as the format string in a call to snprintf().
  This bug becomes exploitable only when a user is able
  to write to a share which utilizes Samba's afsacl.so library
  for setting Windows NT access control lists on files residing
  on an AFS file system.");

  script_tag(name:"affected", value:"Samba versions 3.0.6 through 3.0.23d.");

  script_tag(name:"solution", value:"Update to version 3.0.24 or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2007-0452.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2007-0454.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "3.0.6", test_version2: "3.0.23d")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
