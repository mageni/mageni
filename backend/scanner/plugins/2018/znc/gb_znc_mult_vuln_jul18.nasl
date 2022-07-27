###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_znc_mult_vuln_jul18.nasl 11317 2018-09-11 08:57:27Z asteins $
#
# ZNC < 1.7.1-rc1 Multiple Vulnerabilities
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:znc:znc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108452");
  script_version("$Revision: 11317 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 10:57:27 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-07-24 09:57:02 +0200 (Tue, 24 Jul 2018)");
  script_cve_id("CVE-2018-14055", "CVE-2018-14056");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ZNC < 1.7.1-rc1 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("znc_detect.nasl");
  script_mandatory_keys("znc/installed");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q3/43");
  script_xref(name:"URL", value:"https://wiki.znc.in/ChangeLog/1.7.1");
  script_xref(name:"URL", value:"https://github.com/znc/znc/commit/a7bfbd93812950b7444841431e8e297e62cb524e");
  script_xref(name:"URL", value:"https://github.com/znc/znc/commit/d22fef8620cdd87490754f607e7153979731c69d");
  script_xref(name:"URL", value:"https://github.com/znc/znc/commit/a4a5aeeb17d32937d8c7d743dae9a4cc755ce773");

  script_tag(name:"summary", value:"The host is running an ZCN IRC bouncer which is prone to multiple
  security vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows:

  - unauthenticated users to access restricted directories and files outside of the web server's root directory

  - a non-admin user to escalate his privilege and inject rogue values into znc.conf.");

  script_tag(name:"affected", value:"ZNC before 1.7.1-rc1.");

  script_tag(name:"solution", value:"Upgrade to ZNC 1.7.1-rc1 or later. Please see the references for more information.");

  script_tag(name:"insight", value:"The flaws exist due to,

  - a path traversal flaw via ../ in a web skin name to access files outside of the intended skins directories.

  - ZNC not properly validate untrusted lines coming from the network, allowing a non-admin user to escalate his privilege and
  inject rogue values into znc.conf.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"0.045", test_version2:"1.7.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.7.1-rc1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
