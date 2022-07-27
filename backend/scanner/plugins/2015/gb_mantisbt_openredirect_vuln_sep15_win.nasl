###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_openredirect_vuln_sep15_win.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT Open Redirect Vulnerability September15 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805972");
  script_version("$Revision: 12818 $");
  script_cve_id("CVE-2015-1042");
  script_bugtraq_id(71988);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2015-09-07 12:56:25 +0530 (Mon, 07 Sep 2015)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MantisBT Open Redirect Vulnerability September15 (Windows)");

  script_tag(name:"summary", value:"This host is running MantisBT and is prone
  to open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to use of an incorrect regular
  expression within string_sanitize_url function in core/string_api.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing.");

  script_tag(name:"affected", value:"MantisBT versions 1.2.0a3 through 1.2.18
  on Windows");

  script_tag(name:"solution", value:"Upgrade to version 1.2.19 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/130142");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/110");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/01/10/5");

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

if(version_in_range(version:mantisVer, test_version:"1.2.0", test_version2:"1.2.18")) {
  report = report_fixed_ver(installed_version: mantisVer, fixed_version: "1.2.19");
  security_message(data:report, port:mantisPort);
  exit(0);
}

exit(99);
