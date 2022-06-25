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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112499");
  script_version("2019-04-16T07:10:04+0000");
  script_tag(name:"last_modification", value:"2019-04-16 07:10:04 +0000 (Tue, 16 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-01-24 15:36:12 +0100 (Thu, 24 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-6502");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("OpenSC <= 0.19.0 Memory Leak Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opensc_detect_win.nasl");
  script_mandatory_keys("opensc/win/detected");

  script_tag(name:"summary", value:"OpenSC is prone to a memory leak vulnerability.");
  script_tag(name:"insight", value:"sc_context_create in ctx.c in libopensc in OpenSC has a memory leak, via a call from eidenv.c.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"OpenSC through version 0.19.0.");
  script_tag(name:"solution", value:"No known solution is available as of 03rd April, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/OpenSC/OpenSC/issues/1586");

  exit(0);
}

CPE = "cpe:/a:opensc-project:opensc";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version: vers, test_version: "0.19.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "None", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
