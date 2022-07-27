###############################################################################
# OpenVAS Vulnerability Test
#
# OpenSSH Security Bypass Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806049");
  script_version("2019-05-22T07:58:25+0000");
  script_cve_id("CVE-2015-5352");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-22 07:58:25 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2015-09-10 14:36:41 +0530 (Thu, 10 Sep 2015)");
  script_name("OpenSSH Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/07/01/10");

  script_tag(name:"summary", value:"This host is running OpenSSH and is prone
  to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the refusal
  deadline was not checked within the x11_open_helper function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass intended access restrictions.");

  script_tag(name:"affected", value:"OpenSSH versions before 6.9.");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 6.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"6.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.9", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );