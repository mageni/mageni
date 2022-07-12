###############################################################################
# OpenVAS Vulnerability Test
#
# OpenSSH 'sftp-server' Security Bypass Vulnerability (Windows)
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812050");
  script_version("2019-05-21T12:48:06+0000");
  script_cve_id("CVE-2017-15906");
  script_bugtraq_id(101552);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-21 12:48:06 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2017-10-27 13:03:59 +0530 (Fri, 27 Oct 2017)");
  script_name("OpenSSH 'sftp-server' Security Bypass Vulnerability (Windows)");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssh/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.openssh.com/txt/release-7.6");
  script_xref(name:"URL", value:"https://github.com/openbsd/src/commit/a6981567e8e");

  script_tag(name:"summary", value:"This host is installed with openssh and
  is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the 'process_open' function
  in sftp-server.c script which does not properly prevent write operations in
  readonly mode.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows
  local users to bypass certain security restrictions and perform unauthorized
  actions. This may lead to further attacks.");

  script_tag(name:"affected", value:"OpenSSH versions before 7.6 on Windows");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 7.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.6", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);