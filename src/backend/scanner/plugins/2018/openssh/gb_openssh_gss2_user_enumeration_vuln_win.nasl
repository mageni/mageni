###############################################################################
# OpenVAS Vulnerability Test
#
# OpenSSH 'auth2-gss.c' User Enumeration Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813887");
  script_version("2019-05-21T12:48:06+0000");
  script_cve_id("CVE-2018-15919");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-21 12:48:06 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2018-09-05 13:12:09 +0530 (Wed, 05 Sep 2018)");
  script_name("OpenSSH 'auth2-gss.c' User Enumeration Vulnerability (Windows)");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssh/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=1106163");
  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2018/q3/180");

  script_tag(name:"summary", value:"This host is installed with openssh and
  is prone to user enumeration vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the 'auth-gss2.c' source
  code file of the affected software and is due to insufficient validation of
  an authentication request packet when the Guide Star Server II (GSS2) component
  is used on an affected system.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attacker to harvest valid user accounts, which may aid in brute-force attacks.");

  script_tag(name:"affected", value:"OpenSSH version 5.9 to 7.8 on Windows.");

  script_tag(name:"solution", value:"No known solution is available as of 21th May, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if((revcomp(a:vers, b:"7.8p1") <= 0) && (revcomp(a:vers, b:"5.9") >= 0)) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);