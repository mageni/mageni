###############################################################################
# OpenVAS Vulnerability Test
#
# Novell / NetIQ eDirectory Multiple Vulnerabilities - Mar17
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140224");
  script_version("2019-05-10T14:24:23+0000");
  script_cve_id("CVE-2016-9167", "CVE-2016-9168", "CVE-2017-5186");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-30 12:28:05 +0200 (Thu, 30 Mar 2017)");
  script_name("Novell eDirectory Multiple Vulnerabilities - Mar17");
  script_tag(name:"summary", value:"This host is installed with Novell / NetIQ eDirectory
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- Security scan shows potential Clickjacking vulnerability (Bug 998565) (CVE-2016-9168)

  - Includes a security fix to address potential access inconsistencies (Bug 993219) (CVE-2016-9167)

  - Uses a deprecated MD5 hashing algorithm in a communications certificate (CVE-2017-5186)");

  script_tag(name:"affected", value:"Novell / NetIQ eDirectory versions prior to 9.0.2 Hotfix 2");

  script_tag(name:"solution", value:"Upgrade to Novell / NetIQ eDirectory 9.0.2 Hotfix 2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7016794");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("novell_edirectory_detect.nasl");
  script_mandatory_keys("eDirectory/installed");
  script_require_ports("Services/ldap", 389, 636);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = make_list( "cpe:/a:novell:edirectory", "cpe:/a:netiq:edirectory" );

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! major = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( major !~ "^9\." ) exit( 99 );

if( ! sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" ) )
  sp = "0";

instvers = major;

if( sp > 0 )
  instvers += ' SP' + sp;

revision = get_kb_item( "ldap/eDirectory/" + port + "/build" );
revision = str_replace( string:revision, find:".", replace:"" );

if( version_is_less( version:major, test_version:"9.0.2" ) ||
    ( major == "9.0.2" && int( revision ) < 4000456 )
  )
{
  report = 'Installed version: ' + instvers + '\n' +
           'Fixed version:     9.0.2 Hotfix 2\n';
  security_message(data:report, port:port);
  exit(0);
}

