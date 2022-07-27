###############################################################################
# OpenVAS Vulnerability Test
#
# PuTTY SCP Multiple Spoofing Vulnerabilities (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:putty:putty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814661");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2019-6109", "CVE-2019-6110");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-01-17 15:17:22 +0530 (Thu, 17 Jan 2019)");
  script_tag(name:"qod_type", value:"registry");

  script_name("PuTTY SCP Multiple Spoofing Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with PuTTY and is
  prone to multiple spoofing vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A missing character encoding in the progress display, the object name
    can be used to manipulate the client output.

  - Accepting and displaying arbitrary stderr output from the scp server, a
    malicious server can manipulate the client output.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  servers to spoof the client output.");

  script_tag(name:"affected", value:"PuTTY version 0.70 and earlier on Windows.");

  script_tag(name:"solution", value:"Update to version 0.71 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt");
  script_xref(name:"URL", value:"https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/pscp-unsanitised-server-output.html");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_putty_portable_detect.nasl");
  script_mandatory_keys("putty/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
putVer = infos['version'];
path = infos['location'];

if(version_is_less(version:putVer, test_version:"0.71")) {
  report = report_fixed_ver(installed_version:putVer, fixed_version:"0.71", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
