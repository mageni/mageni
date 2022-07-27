###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_mult_vuln_dec15_win.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT Multiple Vulnerabilities December15 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806640");
  script_version("$Revision: 12818 $");
  script_cve_id("CVE-2014-9270", "CVE-2014-9279", "CVE-2014-9269");
  script_bugtraq_id(71372, 71359, 71368);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2015-12-03 15:38:29 +0530 (Thu, 03 Dec 2015)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MantisBT Multiple Vulnerabilities December15 (Windows)");

  script_tag(name:"summary", value:"This host is running MantisBT and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - the function 'projax_array_serialize_for_autocomplete' within
  core/projax_api.php script doesn't validate input passed by the user.

  - the unattended upgrade script retrieved DB connection settings from POST
  parameters allows an attacker to get the script to connect to their host with
  the current DB config credentials.

  - the input passed via project cookie to helper_api.php script is not validated
  before returning it to user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via the 'profile/Platform'
  field and gain access to sensitive information.");

  script_tag(name:"affected", value:"MantisBT versions 1.1.0a3 through 1.2.x
  before 1.2.18");

  script_tag(name:"solution", value:"Upgrade to version 1.2.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q4/902");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q4/863");
  script_xref(name:"URL", value:"https://www.mantisbt.org/bugs/view.php?id=17583");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.mantisbt.org");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!mantisPort = get_app_port(cpe:CPE))
  exit(0);

if(!mantisVer = get_app_version(cpe:CPE, port:mantisPort))
  exit(0);

##Versions 1.1.0a2 and 1.1.0a1 are not affected
if(mantisVer == "1.1.0a2" || mantisVer == "1.1.0a1")
  exit(0);

if(version_in_range(version:mantisVer, test_version:"1.1.0", test_version2:"1.2.17")) {
  report = report_fixed_ver(installed_version: mantisVer, fixed_version: "1.2.18");
  security_message(data:report, port:mantisPort);
  exit(0);
}

exit(99);
